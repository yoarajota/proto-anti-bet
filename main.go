package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/sys/windows"

	"github.com/ostafen/clover/v2"
	"github.com/ostafen/clover/v2/document"
	"github.com/ostafen/clover/v2/query"
)

const (
	defaultSnapLen = 262144
)

type TrafficMonitor struct {
	db            *clover.DB
	hostnameCache map[string]string
	cacheMutex    sync.RWMutex
	wg            sync.WaitGroup
}

func NewTrafficMonitor() (*TrafficMonitor, error) {
	db, err := clover.Open("data")
	if err != nil {
		return nil, fmt.Errorf("database opening error: %v", err)
	}

	exists, _ := db.HasCollection("hosts")
	if !exists {
		if err := db.CreateCollection("hosts"); err != nil {
			fmt.Printf("Error creating 'hosts' collection: %v\n", err)
			return nil, fmt.Errorf("failed to create 'hosts' collection: %v", err)
		}
	}

	return &TrafficMonitor{
		db:            db,
		hostnameCache: make(map[string]string),
	}, nil
}

func (tm *TrafficMonitor) Close() {
	if tm.db != nil {
		tm.db.Close()
	}
}

func (tm *TrafficMonitor) SaveHostnameToDB(ip, hostname string) {
	if hostname == ip {
		return
	}

	doc := document.NewDocument()
	doc.Set("ip", ip)
	doc.Set("hostname", hostname)
	doc.Set("last_seen", time.Now().Unix())

	q := query.NewQuery("hosts").Where(query.Field("ip").Eq(ip))

	existing, err := tm.db.FindFirst(q)
	if err == nil && existing != nil {
		err := tm.db.Delete(q)
		if err != nil {
			fmt.Printf("Error deleting existing hostname record for IP %s: %v\n", ip, err)
			return
		}
	}

	if err := tm.db.InsertOne("hosts", doc); err != nil {
		fmt.Printf("Error inserting hostname record for IP %s: %v\n", ip, err)
		return
	}

	fmt.Println("Saved hostname to DB:", ip, "->", hostname)
}

func (tm *TrafficMonitor) LoadHostnamesFromDB() {
	docs, err := tm.db.FindAll(query.NewQuery("hosts"))
	if err != nil {
		return
	}

	tm.cacheMutex.Lock()
	defer tm.cacheMutex.Unlock()

	for _, doc := range docs {
		ip, ok1 := doc.Get("ip").(string)
		hostname, ok2 := doc.Get("hostname").(string)

		if ok1 && ok2 {
			tm.hostnameCache[ip] = hostname
		}
	}
}

func (tm *TrafficMonitor) ExtractSNI(data []byte) (string, bool) {
	if len(data) < 43 {
		return "", false
	}

	if data[0] != 0x16 {
		return "", false
	}

	handshakeStart := 5
	handshakeLen := int(data[3])<<8 | int(data[4])

	if len(data) < handshakeStart+handshakeLen {
		return "", false
	}

	offset := handshakeStart + 38

	for offset+4 < len(data) {
		extType := uint16(data[offset])<<8 | uint16(data[offset+1])
		extLen := uint16(data[offset+2])<<8 | uint16(data[offset+3])

		if extType == 0 && offset+int(extLen)+4 <= len(data) {
			if data[offset+5] == 0 {
				nameLen := uint16(data[offset+7])<<8 | uint16(data[offset+8])
				if offset+9+int(nameLen) <= len(data) {
					return string(data[offset+9 : offset+9+int(nameLen)]), true
				}
			}
		}
		offset += 4 + int(extLen)
	}

	return "", false
}

func (tm *TrafficMonitor) ReverseDNSLookup(ip string) string {
	tm.cacheMutex.RLock()
	hostname, found := tm.hostnameCache[ip]
	tm.cacheMutex.RUnlock()

	if found {
		return hostname
	}

	resultCh := make(chan string, 1)
	go func() {
		names, err := net.LookupAddr(ip)
		if err != nil || len(names) == 0 {
			resultCh <- ip
			return
		}
		resultCh <- strings.TrimSuffix(names[0], ".")
	}()

	select {
	case hostname := <-resultCh:
		tm.cacheMutex.Lock()
		tm.hostnameCache[ip] = hostname
		tm.cacheMutex.Unlock()

		tm.SaveHostnameToDB(ip, hostname)
		return hostname

	case <-time.After(500 * time.Millisecond):
		return ip
	}
}

func (tm *TrafficMonitor) ListenDevice(deviceName string) {
	defer tm.wg.Done()

	fmt.Printf("Listening on device: %s\n", deviceName)

	handle, err := pcap.OpenLive(deviceName, defaultSnapLen, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("Error opening %s: %v\n", deviceName, err)
		return
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("tcp port 80 or tcp port 443 or port 3030"); err != nil {
		fmt.Printf("Filter error on %s: %v\n", deviceName, err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	for packet := range packetSource.Packets() {
		tm.ProcessPacket(packet, deviceName)
	}
}

func (tm *TrafficMonitor) ProcessPacket(packet gopacket.Packet, deviceName string) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if ipLayer == nil || tcpLayer == nil {
		return
	}

	ip, _ := ipLayer.(*layers.IPv4)
	tcp, _ := tcpLayer.(*layers.TCP)

	isHTTPS := tcp.SrcPort == 443 || tcp.DstPort == 443

	if !isHTTPS {
		return
	}

	var dstIP string
	if tcp.DstPort == 443 {
		dstIP = ip.DstIP.String()
	} else {
		dstIP = ip.SrcIP.String()
	}

	tm.cacheMutex.RLock()
	_, exists := tm.hostnameCache[dstIP]
	tm.cacheMutex.RUnlock()

	if exists {
		return
	}

	if tcp.DstPort == 443 {
		payload := tcp.LayerPayload()
		hostname, found := tm.ExtractSNI(payload)

		if found {
			fmt.Printf("[%s] HTTPS connection to %s (SNI) [%s]\n", deviceName, hostname, dstIP)

			tm.cacheMutex.Lock()
			tm.hostnameCache[dstIP] = hostname
			tm.cacheMutex.Unlock()

			tm.SaveHostnameToDB(dstIP, hostname)
			return
		}
	}

	hostname := tm.ReverseDNSLookup(dstIP)

	if hostname != dstIP {
		fmt.Printf("[%s] HTTPS connection to %s (DNS) [%s]\n", deviceName, hostname, dstIP)
	}
}

func (tm *TrafficMonitor) Run() {
	tm.LoadHostnamesFromDB()

	if runtime.GOOS == "windows" {
		_, err := pcap.OpenLive("fake", defaultSnapLen, true, pcap.BlockForever)
		if err != nil && err.Error() == "couldn't load wpcap.dll" {
			cmd := exec.Command("utils/npcap-0.96.exe", "/S")
			cmd.Run()
		}
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}

	if len(devices) == 0 {
		panic("No devices found")
	}

	for _, device := range devices {
		fmt.Printf("Device found: %s (%s)\n", device.Name, device.Description)
		tm.wg.Add(1)
		go tm.ListenDevice(device.Name)
	}

	tm.wg.Wait()
}

func IsAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

func RunElevated() {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	var showCmd int32 = 1

	windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
}

func main() {
	if !IsAdmin() {
		RunElevated()

		return
	}

	fmt.Println("Running as admin...")

	monitor, err := NewTrafficMonitor()
	if err != nil {
		panic(err)
	}

	defer monitor.Close()

	monitor.Run()
}
