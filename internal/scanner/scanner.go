package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gatiella/cctv-scanner/configs"
	"github.com/gatiella/cctv-scanner/internal/detector"
	"github.com/gatiella/cctv-scanner/pkg/models"
)

// Scanner handles network scanning operations
type Scanner struct {
	config          *configs.Config
	detector        *detector.Detector
	portScanner     *PortScanner     // NEW
	serviceDetector *ServiceDetector // NEW
}

// NewScanner creates a new Scanner instance
func NewScanner(config *configs.Config) *Scanner {
	return &Scanner{
		config:          config,
		detector:        detector.NewDetector(config),
		portScanner:     NewPortScanner(config),     // NEW
		serviceDetector: NewServiceDetector(config), // NEW
	}
}

// ScanNetwork scans the given CIDR range for CCTV devices (CLI version)
func (s *Scanner) ScanNetwork(cidr string) []*models.Device {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Printf("❌ Error parsing CIDR: %v\n", err)
		return nil
	}

	var devices []*models.Device
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, s.config.MaxConcurrent)

	ipCount := 0
	for testIP := ip.Mask(ipnet.Mask); ipnet.Contains(testIP); inc(testIP) {
		ipCount++
	}

	scanned := 0
	progressInterval := ipCount / 20
	if progressInterval < 1 {
		progressInterval = 1
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		wg.Add(1)
		sem <- struct{}{}

		go func(ipStr string) {
			defer wg.Done()
			defer func() { <-sem }()

			if device := s.scanIP(ipStr); device != nil {
				mu.Lock()
				devices = append(devices, device)
				fmt.Printf("✅ Found device: %s:%d (%d open ports)\n", device.IP, device.Port, len(device.OpenPorts))
				mu.Unlock()
			}

			mu.Lock()
			scanned++
			if scanned%progressInterval == 0 {
				progress := float64(scanned) / float64(ipCount) * 100
				fmt.Printf("📊 Progress: %.1f%% (%d/%d IPs)\n", progress, scanned, ipCount)
			}
			mu.Unlock()
		}(ip.String())
	}

	wg.Wait()
	return devices
}

// ScanNetworkWithProgress scans with progress callback for API/Flutter
func (s *Scanner) ScanNetworkWithProgress(cidr string, progressCallback func(int, string)) []*models.Device {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		if progressCallback != nil {
			progressCallback(0, fmt.Sprintf("Error parsing CIDR: %v", err))
		}
		return nil
	}

	var devices []*models.Device
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, s.config.MaxConcurrent)

	ipCount := 0
	for testIP := ip.Mask(ipnet.Mask); ipnet.Contains(testIP); inc(testIP) {
		ipCount++
	}

	scanned := 0
	progressInterval := ipCount / 20
	if progressInterval < 1 {
		progressInterval = 1
	}

	if progressCallback != nil {
		progressCallback(0, fmt.Sprintf("Starting scan of %d IPs...", ipCount))
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		wg.Add(1)
		sem <- struct{}{}

		go func(ipStr string) {
			defer wg.Done()
			defer func() { <-sem }()

			if device := s.scanIP(ipStr); device != nil {
				mu.Lock()
				devices = append(devices, device)
				if progressCallback != nil {
					progressCallback(
						int(float64(scanned)/float64(ipCount)*100),
						fmt.Sprintf("Found device: %s (ports: %d)", device.IP, len(device.OpenPorts)),
					)
				}
				mu.Unlock()
			}

			mu.Lock()
			scanned++
			if scanned%progressInterval == 0 && progressCallback != nil {
				progress := int(float64(scanned) / float64(ipCount) * 100)
				progressCallback(progress, fmt.Sprintf("Scanned %d/%d IPs, found %d devices", scanned, ipCount, len(devices)))
			}
			mu.Unlock()
		}(ip.String())
	}

	wg.Wait()

	if progressCallback != nil {
		progressCallback(100, fmt.Sprintf("Scan complete! Found %d devices", len(devices)))
	}

	return devices
}

// scanIP checks a single IP for CCTV devices and performs detailed scanning
func (s *Scanner) scanIP(ip string) *models.Device {
	// First, check CCTV ports quickly
	for _, port := range s.config.CCTVPorts {
		if isPortOpen(ip, port, s.config.Timeout) {
			device := models.NewDevice(ip, port)

			// NEW: Perform detailed port scan
			if s.config.EnableFullPortScan {
				s.portScanner.ScanAllPorts(device)
			}

			// NEW: Detect services
			if s.config.ServiceDetection {
				s.serviceDetector.DetectServices(device)
			}

			// Run vulnerability checks
			s.detector.DetectDevice(device)

			return device
		}
	}
	return nil
}

// isPortOpen checks if a TCP port is open
func isPortOpen(ip string, port int, timeout time.Duration) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// inc increments an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}