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
)

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

var hostnameCache = make(map[string]string)
var cacheMutex sync.RWMutex

func extractSNI(data []byte) (string, bool) {
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

func reverseDNSLookup(ip string) string {
	cacheMutex.RLock()

	hostname, found := hostnameCache[ip]

	if found {
		cacheMutex.RUnlock()

		return hostname
	}

	cacheMutex.RUnlock()

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
		cacheMutex.Lock()
		hostnameCache[ip] = hostname
		cacheMutex.Unlock()

		return hostname
	case <-time.After(500 * time.Millisecond):
		return ip
	}
}

func amAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")

	return err == nil
}

func runMeElevated() {
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

func listenDevice(deviceName string, wg *sync.WaitGroup) {
	defer wg.Done()

	fmt.Printf("Listening to: %s\n", deviceName)

	handle, err := pcap.OpenLive(deviceName, defaultSnapLen, false, pcap.BlockForever)

	if err != nil {
		fmt.Printf("Erro ao abrir %s: %v\n", deviceName, err)
		return
	}

	defer handle.Close()

	// Filtrar tráfego HTTP (porta 80), HTTPS (porta 443), e também manter porta 3030
	if err := handle.SetBPFFilter("tcp port 80 or tcp port 443 or port 3030"); err != nil {
		fmt.Printf("Error in filter %s: %v\n", deviceName, err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		if ipLayer != nil && tcpLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			tcp, _ := tcpLayer.(*layers.TCP)

			isHTTPS := tcp.SrcPort == 443 || tcp.DstPort == 443

			if isHTTPS {
				var dstIP string
				var hostname string
				var found bool = false

				if tcp.DstPort == 443 {
					dstIP = ip.DstIP.String()
				} else {
					dstIP = ip.SrcIP.String()
				}

				if tcp.DstPort == 443 {
					payload := tcp.LayerPayload()

					hostname, found := extractSNI(payload)

					if found {
						cacheMutex.RLock()
						_, exists := hostnameCache[dstIP]
						cacheMutex.RUnlock()

						if !exists {
							fmt.Printf("[%s] HTTPS connection %s (SNI) [%s]\n", deviceName, hostname, dstIP)

							cacheMutex.Lock()
							hostnameCache[dstIP] = hostname
							cacheMutex.Unlock()
						}

						continue
					}
				}

				_, exists := hostnameCache[dstIP]

				if !exists {
					fmt.Printf("[%s] HTTPS connection %s (DNS) [%s]\n", deviceName, hostname, dstIP)
				}

				if tcp.DstPort != 443 || !found {
					cacheMutex.RLock()
					_, exists := hostnameCache[dstIP]
					cacheMutex.RUnlock()

					if !exists {
						hostname = reverseDNSLookup(dstIP)

						if hostname != dstIP {
							fmt.Printf("[%s] HTTPS connection %s (DNS) [%s]\n", deviceName, hostname, dstIP)
						}
					}
				}
			}
		}
	}
}

func main() {
	if !amAdmin() {
		runMeElevated()

		return
	}

	if runtime.GOOS == "windows" {
		_, err := pcap.OpenLive("fake", defaultSnapLen, true, pcap.BlockForever)

		if err != nil && err.Error() == "couldn't load wpcap.dll" {
			// silent install WinPcap / utils/npcap-0.96.exe\
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

	var wg sync.WaitGroup

	for _, device := range devices {
		fmt.Printf("Device found: %s (%s)\n", device.Name, device.Description)
		wg.Add(1)
		go listenDevice(device.Name, &wg)
	}

	wg.Wait()
}
