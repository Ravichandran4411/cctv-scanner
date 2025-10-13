package fingerprint

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/gatiella/cctv-scanner/pkg/models"
)

// Fingerprinter handles device fingerprinting and OS detection
type Fingerprinter struct {
	macVendorDB map[string]string
}

// NewFingerprinter creates a new fingerprinter
func NewFingerprinter() *Fingerprinter {
	f := &Fingerprinter{
		macVendorDB: getMACVendorDatabase(),
	}
	return f
}

// FingerprintDevice performs comprehensive device fingerprinting
func (f *Fingerprinter) FingerprintDevice(device *models.Device) {
	// Get MAC address
	macAddr := f.getMACAddress(device.IP)
	if macAddr != "" {
		device.MACAddress = macAddr
		device.Vendor = f.lookupMACVendor(macAddr)
	}

	// Detect OS via TTL
	if device.OS == "" {
		device.OS = f.detectOSByTTL(device.IP)
	}

	// Get hostname
	if device.HostName == "" {
		device.HostName = f.getHostname(device.IP)
	}

	// Classify device type based on all gathered info
	if device.DeviceType == "" {
		device.DeviceType = f.classifyDevice(device)
	}

	// Enhanced manufacturer detection
	if device.Manufacturer == "" || device.Manufacturer == "Unknown" {
		device.Manufacturer = f.detectManufacturer(device)
	}
}

// detectOSByTTL detects OS based on TTL value from ping
func (f *Fingerprinter) detectOSByTTL(ip string) string {
	ttl := f.getTTL(ip)
	if ttl == 0 {
		return "Unknown"
	}

	// TTL-based OS detection
	switch {
	case ttl <= 64 && ttl > 32:
		return "Linux/Unix"
	case ttl <= 128 && ttl > 64:
		return "Windows"
	case ttl <= 255 && ttl > 128:
		return "Cisco/Network Device"
	case ttl <= 32:
		return "IoT Device"
	default:
		return "Unknown"
	}
}

// getTTL gets the TTL value from ping response
func (f *Fingerprinter) getTTL(ip string) int {
	var cmd *exec.Cmd
	
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", "1000", ip)
	case "darwin":
		cmd = exec.Command("ping", "-c", "1", "-W", "1000", ip)
	default: // linux
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0
	}

	// Parse TTL from output
	ttlRegex := regexp.MustCompile(`ttl=(\d+)|TTL=(\d+)`)
	matches := ttlRegex.FindStringSubmatch(string(output))
	
	if len(matches) > 1 {
		var ttl int
		if matches[1] != "" {
			fmt.Sscanf(matches[1], "%d", &ttl)
		} else if matches[2] != "" {
			fmt.Sscanf(matches[2], "%d", &ttl)
		}
		return ttl
	}

	return 0
}

// getMACAddress gets MAC address via ARP
func (f *Fingerprinter) getMACAddress(ip string) string {
	var cmd *exec.Cmd
	
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("arp", "-a", ip)
	default:
		cmd = exec.Command("arp", "-n", ip)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}

	// Parse MAC address from ARP output
	macRegex := regexp.MustCompile(`([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})`)
	mac := macRegex.FindString(string(output))
	
	return strings.ToUpper(strings.ReplaceAll(mac, "-", ":"))
}

// lookupMACVendor looks up vendor from MAC address
func (f *Fingerprinter) lookupMACVendor(mac string) string {
	if mac == "" {
		return "Unknown"
	}

	// Get OUI (first 3 octets)
	parts := strings.Split(mac, ":")
	if len(parts) < 3 {
		return "Unknown"
	}

	oui := strings.Join(parts[:3], ":")
	
	if vendor, exists := f.macVendorDB[oui]; exists {
		return vendor
	}

	return "Unknown"
}

// getHostname attempts to get hostname via reverse DNS
func (f *Fingerprinter) getHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	
	// Return first hostname without trailing dot
	hostname := names[0]
	return strings.TrimSuffix(hostname, ".")
}

// classifyDevice classifies device type based on all available information
func (f *Fingerprinter) classifyDevice(device *models.Device) string {
	// Check services first
	for _, service := range device.Services {
		serviceType := strings.ToLower(service.Name)
		
		// CCTV/Camera detection
		if strings.Contains(serviceType, "camera") || 
		   strings.Contains(serviceType, "rtsp") ||
		   strings.Contains(serviceType, "hikvision") ||
		   strings.Contains(serviceType, "dahua") ||
		   strings.Contains(serviceType, "axis") {
			return "IP Camera"
		}
		
		// Database servers
		if strings.Contains(serviceType, "mysql") ||
		   strings.Contains(serviceType, "postgresql") ||
		   strings.Contains(serviceType, "mongodb") ||
		   strings.Contains(serviceType, "redis") {
			return "Database Server"
		}
		
		// Web servers
		if strings.Contains(serviceType, "apache") ||
		   strings.Contains(serviceType, "nginx") ||
		   strings.Contains(serviceType, "iis") {
			return "Web Server"
		}
	}

	// Check open ports
	for _, port := range device.OpenPorts {
		switch port.Port {
		case 554, 8000, 37777:
			return "IP Camera"
		case 445, 139, 3389:
			return "Windows Computer"
		case 22:
			if device.OS == "Linux/Unix" {
				return "Linux Server"
			}
		case 631, 9100:
			return "Printer"
		case 80, 443, 8080:
			if len(device.OpenPorts) == 1 {
				return "Web Server"
			}
		}
	}

	// Check vendor
	vendor := strings.ToLower(device.Vendor)
	if strings.Contains(vendor, "hikvision") || strings.Contains(vendor, "dahua") {
		return "IP Camera"
	}
	if strings.Contains(vendor, "apple") {
		return "Apple Device"
	}
	if strings.Contains(vendor, "samsung") || strings.Contains(vendor, "xiaomi") {
		return "Mobile Device"
	}
	if strings.Contains(vendor, "cisco") || strings.Contains(vendor, "juniper") {
		return "Network Equipment"
	}
	if strings.Contains(vendor, "synology") || strings.Contains(vendor, "qnap") {
		return "NAS Device"
	}

	// Check OS
	if device.OS == "Windows" {
		return "Windows Computer"
	}
	if device.OS == "Linux/Unix" {
		return "Linux Computer"
	}
	if device.OS == "Cisco/Network Device" {
		return "Network Equipment"
	}
	if device.OS == "IoT Device" {
		return "IoT Device"
	}

	return "Unknown Device"
}

// detectManufacturer detects manufacturer from various sources
func (f *Fingerprinter) detectManufacturer(device *models.Device) string {
	// Priority 1: Vendor from MAC
	if device.Vendor != "" && device.Vendor != "Unknown" {
		return device.Vendor
	}

	// Priority 2: From services
	for _, service := range device.Services {
		if mfg := service.ExtraInfo["manufacturer"]; mfg != "" {
			return mfg
		}
		
		serviceName := strings.ToLower(service.Name)
		if strings.Contains(serviceName, "hikvision") {
			return "Hikvision"
		}
		if strings.Contains(serviceName, "dahua") {
			return "Dahua"
		}
		if strings.Contains(serviceName, "axis") {
			return "Axis Communications"
		}
	}

	// Priority 3: From device type
	if device.DeviceType != "" && device.DeviceType != "Unknown Device" {
		return device.DeviceType
	}

	return "Unknown"
}