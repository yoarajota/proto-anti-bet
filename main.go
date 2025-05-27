package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/sys/windows"
)

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

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
		fmt.Printf("Erro ao configurar filtro para %s: %v\n", deviceName, err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	fmt.Printf("Capturando pacotes HTTP em %s...\n", deviceName)

	for packet := range packetSource.Packets() {
		// Analisa apenas as camadas TCP que podem conter HTTP
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			// Verifica se é uma porta HTTP/HTTPS
			isHTTP := tcp.SrcPort == 80 || tcp.DstPort == 80
			isHTTPS := tcp.SrcPort == 443 || tcp.DstPort == 443

			if isHTTP || isHTTPS {
				applicationLayer := packet.ApplicationLayer()
				if applicationLayer != nil {
					payload := applicationLayer.Payload()

					// Protocolo
					protocol := "HTTP"
					if isHTTPS {
						protocol = "HTTPS"
					}

					// Verifica se parece ser um cabeçalho HTTP
					payloadStr := string(payload)
					if strings.Contains(payloadStr, "HTTP/1.") ||
						strings.Contains(payloadStr, "GET ") ||
						strings.Contains(payloadStr, "POST ") ||
						strings.Contains(payloadStr, "Host:") {

						fmt.Printf("\n[%s] %s Pacote capturado:\n", deviceName, protocol)

						// Mostra as primeiras linhas (normalmente contém método, URL, etc)
						lines := strings.Split(payloadStr, "\n")
						for i, line := range lines {
							if i > 10 || line == "" { // Limita a 10 linhas ou para na primeira linha vazia
								break
							}
							fmt.Printf("  %s\n", strings.TrimSpace(line))
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
