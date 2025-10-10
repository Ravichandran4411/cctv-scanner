package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/gatiella/cctv-scanner/configs"
	"github.com/gatiella/cctv-scanner/internal/reporter"
	"github.com/gatiella/cctv-scanner/internal/scanner"
	"github.com/gatiella/cctv-scanner/pkg/models"
)

func main() {
	printBanner()
	
	// Get user consent
	if !getUserConsent() {
		fmt.Println("Scan cancelled.")
		return
	}

	// Get network range (auto-detect or manual)
	networkRange := getNetworkRangeWithAutoDetect()
	if networkRange == "" {
		fmt.Println("Invalid network range provided.")
		return
	}

	// Initialize scanner
	config := configs.NewDefaultConfig()
	s := scanner.NewScanner(config)

	fmt.Println("\n🔍 Starting network scan...")
	fmt.Println("This may take a few minutes depending on network size...\n")

	// Perform scan
	devices := s.ScanNetwork(networkRange)

	// Generate report
	r := reporter.NewReporter()
	r.GenerateReport(devices)
	
	// Save to file
	if len(devices) > 0 {
		saveReport(r, devices)
	}
}

func printBanner() {
	banner := `
			╔══════════════════════════════════════════════════════════════╗
			║                                                              ║
			║   ██████╗ ██████╗████████╗██╗   ██╗                         ║
			║  ██╔════╝██╔════╝╚══██╔══╝██║   ██║                         ║
			║  ██║     ██║        ██║   ██║   ██║                         ║
			║  ██║     ██║        ██║   ╚██╗ ██╔╝                         ║
			║  ╚██████╗╚██████╗   ██║    ╚████╔╝                          ║
			║   ╚═════╝ ╚═════╝   ╚═╝     ╚═══╝                           ║
			║                                                              ║
			║           Network Security Scanner v1.0                      ║
			║           Ethical Security Assessment Tool                   ║
			║                                                              ║
			║           ⚡ Developed by: gatiella ⚡                        ║
			║           🔒 Secure • Fast • Reliable                        ║
			║                                                              ║
			╚══════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}

func getUserConsent() bool {
	fmt.Println("⚠️  WARNING: Only use this tool on networks you own or have")
	fmt.Println("   explicit written permission to test.\n")
	fmt.Print("Do you have authorization to scan this network? (yes/no): ")
	
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.ToLower(strings.TrimSpace(response))
	
	return response == "yes" || response == "y"
}

func getNetworkRange() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("\nEnter network range (e.g., 192.168.1.0/24): ")
	networkRange, _ := reader.ReadString('\n')
	return strings.TrimSpace(networkRange)
}

func getNetworkRangeWithAutoDetect() string {
	reader := bufio.NewReader(os.Stdin)
	
	// Auto-detect local network interfaces
	interfaces, err := detectNetworkInterfaces()
	if err != nil || len(interfaces) == 0 {
		fmt.Println("❌ Could not auto-detect network interfaces.")
		return getNetworkRange()
	}

	fmt.Println("\n🌐 Detected Network Interfaces:")
	for i, iface := range interfaces {
		fmt.Printf("  [%d] %s - %s (Network: %s)\n", 
			i+1, iface.Name, iface.IP, iface.CIDR)
	}
	fmt.Println("  [M] Enter network range manually")
	
	fmt.Print("\nSelect an option: ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(strings.ToUpper(choice))
	
	if choice == "M" {
		return getNetworkRange()
	}
	
	// Parse numeric choice
	var selectedIndex int
	_, err = fmt.Sscanf(choice, "%d", &selectedIndex)
	if err != nil || selectedIndex < 1 || selectedIndex > len(interfaces) {
		fmt.Println("Invalid selection. Please try again.")
		return getNetworkRangeWithAutoDetect()
	}
	
	selectedNetwork := interfaces[selectedIndex-1].CIDR
	fmt.Printf("\n✅ Selected network: %s\n", selectedNetwork)
	
	// Ask for confirmation
	fmt.Print("Proceed with this network? (yes/no): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.ToLower(strings.TrimSpace(confirm))
	
	if confirm == "yes" || confirm == "y" {
		return selectedNetwork
	}
	
	return getNetworkRangeWithAutoDetect()
}

type NetworkInterface struct {
	Name string
	IP   string
	CIDR string
}

func detectNetworkInterfaces() ([]NetworkInterface, error) {
	var result []NetworkInterface
	
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	
	for _, iface := range ifaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		
		for _, addr := range addrs {
			var ip net.IP
			var network *net.IPNet
			
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
				network = v
			case *net.IPAddr:
				ip = v.IP
			}
			
			// Only IPv4 addresses
			if ip == nil || ip.To4() == nil {
				continue
			}
			
			// Calculate network CIDR
			if network != nil {
				networkIP := ip.Mask(network.Mask)
				cidr := fmt.Sprintf("%s/%d", networkIP.String(), maskSize(network.Mask))
				
				result = append(result, NetworkInterface{
					Name: iface.Name,
					IP:   ip.String(),
					CIDR: cidr,
				})
			}
		}
	}
	
	return result, nil
}

func maskSize(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}

func saveReport(r *reporter.Reporter, devices []*models.Device) {
	fmt.Print("\n💾 Save detailed report to file? (yes/no): ")
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.ToLower(strings.TrimSpace(response))
	
	if response == "yes" || response == "y" {
		filename := r.SaveToFile(devices)
		if filename != "" {
			fmt.Printf("✅ Report saved to: %s\n", filename)
		}
	}
}

