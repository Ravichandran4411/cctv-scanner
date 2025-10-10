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
	config   *configs.Config
	detector *detector.Detector
}

// NewScanner creates a new Scanner instance
func NewScanner(config *configs.Config) *Scanner {
	return &Scanner{
		config:   config,
		detector: detector.NewDetector(config),
	}
}

// ScanNetwork scans the given CIDR range for CCTV devices
func (s *Scanner) ScanNetwork(cidr string) []*models.Device {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Printf("❌ Error parsing CIDR: %v\n", err)
		return nil
	}

	var devices []*models.Device
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	// Semaphore for controlling concurrency
	sem := make(chan struct{}, s.config.MaxConcurrent)

	ipCount := 0
	for testIP := ip.Mask(ipnet.Mask); ipnet.Contains(testIP); inc(testIP) {
		ipCount++
	}

	scanned := 0
	progressInterval := ipCount / 20 // Update every 5%
	if progressInterval < 1 {
		progressInterval = 1
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		wg.Add(1)
		sem <- struct{}{} // Acquire semaphore
		
		go func(ipStr string) {
			defer wg.Done()
			defer func() { <-sem }() // Release semaphore
			
			if device := s.scanIP(ipStr); device != nil {
				mu.Lock()
				devices = append(devices, device)
				fmt.Printf("✅ Found device: %s:%d\n", device.IP, device.Port)
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

// scanIP checks a single IP for CCTV devices on all configured ports
func (s *Scanner) scanIP(ip string) *models.Device {
	for _, port := range s.config.CCTVPorts {
		if isPortOpen(ip, port, s.config.Timeout) {
			device := models.NewDevice(ip, port)
			
			// Run all detections and checks
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