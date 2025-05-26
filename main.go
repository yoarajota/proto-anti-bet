package main

import (
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"fmt"
	"runtime"
	"os/exec"
    "golang.org/x/sys/windows"
    "os"
    "syscall"
	"strings"
)


const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

func amAdmin() bool {
    _, err := os.Open("\\\\.\\PHYSICALDRIVE0")
    if err != nil {
        fmt.Println("admin no")
        return false
    }
    fmt.Println("admin yes")
    return true
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

    var showCmd int32 = 1 //SW_NORMAL

    err := windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
    if err != nil {
        fmt.Println(err)
    }
}

func main() {
	if !amAdmin() {
        runMeElevated()
    }

	if runtime.GOOS == "windows" {
        _, err := pcap.OpenLive("fake", defaultSnapLen, true, pcap.BlockForever)

        if err != nil && err.Error() == "couldn't load wpcap.dll" {
			// silent install WinPcap / utils/npcap-0.96.exe\

			exec.Command("utils/npcap-0.96.exe", "/S").Run()
        }
    }

	handle, err := pcap.OpenLive("eth0", defaultSnapLen, true, pcap.BlockForever)
	
	if err != nil {
		panic(err)
	}

	defer handle.Close()

	if err := handle.SetBPFFilter("port 3030"); err != nil {
		panic(err)
	}

	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()
	
		for pkt := range packets {
		// Your analysis here!
		// print
		fmt.Println(pkt)
	}
}