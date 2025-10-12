package scanner

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gatiella/cctv-scanner/configs"
	"github.com/gatiella/cctv-scanner/pkg/models"
)

// PortScanner handles detailed port scanning
type PortScanner struct {
	config  *configs.Config
	timeout time.Duration
}

// NewPortScanner creates a new port scanner instance
func NewPortScanner(config *configs.Config) *PortScanner {
	return &PortScanner{
		config:  config,
		timeout: config.PortScanTimeout,
	}
}

// ScanAllPorts scans all configured ports on a device
func (ps *PortScanner) ScanAllPorts(device *models.Device) {
	if !ps.config.EnableFullPortScan {
		return
	}

	ports := ps.config.GetPortsToScan()
	
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 50) // Limit concurrent port scans

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			if portInfo := ps.scanPort(device.IP, p); portInfo != nil {
				mu.Lock()
				device.AddPort(*portInfo)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
}

// scanPort scans a single port and returns port info if open
func (ps *PortScanner) scanPort(ip string, port int) *models.PortInfo {
	start := time.Now()
	address := fmt.Sprintf("%s:%d", ip, port)
	
	conn, err := net.DialTimeout("tcp", address, ps.timeout)
	responseTime := int(time.Since(start).Milliseconds())
	
	if err != nil {
		return nil // Port closed or filtered
	}
	defer conn.Close()

	portInfo := &models.PortInfo{
		Port:         port,
		Protocol:     "tcp",
		State:        "open",
		Service:      getServiceName(port),
		ResponseTime: responseTime,
	}

	return portInfo
}

// ScanPortRange scans a specific range of ports
func (ps *PortScanner) ScanPortRange(device *models.Device, startPort, endPort int) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 50)

	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		sem <- struct{}{}

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			if portInfo := ps.scanPort(device.IP, p); portInfo != nil {
				mu.Lock()
				device.AddPort(*portInfo)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
}

// GrabBanner attempts to grab the service banner
func (ps *PortScanner) GrabBanner(ip string, port int) string {
	if !ps.config.BannerGrabbing {
		return ""
	}

	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, ps.timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(ps.timeout))

	// Try to read banner
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		// Some services don't send banner automatically, try sending a probe
		banner = ps.probeBanner(conn, port)
	}

	return strings.TrimSpace(banner)
}

// probeBanner sends a probe based on port and tries to get a response
func (ps *PortScanner) probeBanner(conn net.Conn, port int) string {
	var probe string
	
	switch port {
	case 80, 8080, 8000, 8888:
		probe = "GET / HTTP/1.0\r\n\r\n"
	case 443:
		// HTTPS doesn't work with plain text
		return ""
	case 21:
		// FTP sends banner automatically
		return ""
	case 22:
		// SSH sends banner automatically
		return ""
	case 554:
		probe = "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"
	default:
		probe = "\r\n"
	}

	if probe != "" {
		conn.Write([]byte(probe))
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		
		reader := bufio.NewReader(conn)
		response, _ := reader.ReadString('\n')
		return strings.TrimSpace(response)
	}

	return ""
}

// getServiceName returns the common service name for a port
func getServiceName(port int) string {
	services := map[int]string{
		20:    "ftp-data",
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		445:   "smb",
		554:   "rtsp",
		993:   "imaps",
		995:   "pop3s",
		1433:  "mssql",
		1723:  "pptp",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "postgresql",
		5900:  "vnc",
		8000:  "http-alt",
		8080:  "http-proxy",
		8443:  "https-alt",
		8888:  "http-alt",
		9000:  "camera",
		10554: "rtsp-alt",
		37777: "dahua",
		34567: "dahua-dvr",
	}

	if name, exists := services[port]; exists {
		return name
	}
	return "unknown"
}

// IsPortOpen checks if a specific port is open (quick check)
func (ps *PortScanner) IsPortOpen(ip string, port int) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, ps.timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}