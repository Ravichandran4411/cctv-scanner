package scanner

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gatiella/cctv-scanner/configs"
	"github.com/gatiella/cctv-scanner/pkg/models"
)

// ServiceDetector handles service detection and fingerprinting
type ServiceDetector struct {
	config *configs.Config
}

// NewServiceDetector creates a new service detector
func NewServiceDetector(config *configs.Config) *ServiceDetector {
	return &ServiceDetector{
		config: config,
	}
}

// DetectServices detects services on all open ports
func (sd *ServiceDetector) DetectServices(device *models.Device) {
	if !sd.config.ServiceDetection {
		return
	}

	for _, portInfo := range device.OpenPorts {
		if service := sd.detectService(device.IP, portInfo.Port); service != nil {
			device.AddService(*service)
		}
	}
}

// detectService detects the service running on a specific port
func (sd *ServiceDetector) detectService(ip string, port int) *models.ServiceInfo {
	service := &models.ServiceInfo{
		Port:      port,
		Name:      getServiceName(port),
		ExtraInfo: make(map[string]string),
	}

	// Grab banner
	banner := sd.grabServiceBanner(ip, port)
	service.Banner = banner

	// Detect service type and version
	sd.fingerprintService(service, banner)

	// Additional checks based on port
	switch port {
	case 80, 8080, 8000, 8888, 8081:
		sd.detectHTTPService(ip, port, service)
	case 443, 8443:
		sd.detectHTTPSService(ip, port, service)
	case 554, 10554:
		sd.detectRTSPService(ip, port, service)
	case 21:
		sd.detectFTPService(ip, port, service)
	case 22:
		sd.detectSSHService(ip, port, service)
	case 23:
		sd.detectTelnetService(ip, port, service)
	}

	return service
}

// grabServiceBanner grabs the service banner
func (sd *ServiceDetector) grabServiceBanner(ip string, port int) string {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, sd.config.PortScanTimeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// Try reading automatic banner
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	
	if err != nil || banner == "" {
		// Send probe based on port
		probe := sd.getProbeForPort(port)
		if probe != "" {
			conn.Write([]byte(probe))
			banner, _ = reader.ReadString('\n')
		}
	}

	return strings.TrimSpace(banner)
}

// fingerprintService fingerprints the service from banner
func (sd *ServiceDetector) fingerprintService(service *models.ServiceInfo, banner string) {
	banner = strings.ToLower(banner)

	// HTTP servers
	if strings.Contains(banner, "apache") {
		service.Name = "Apache HTTP Server"
		service.Version = extractVersion(banner, `apache/(\d+\.\d+\.\d+)`)
	} else if strings.Contains(banner, "nginx") {
		service.Name = "Nginx"
		service.Version = extractVersion(banner, `nginx/(\d+\.\d+\.\d+)`)
	} else if strings.Contains(banner, "microsoft-iis") {
		service.Name = "Microsoft IIS"
		service.Version = extractVersion(banner, `microsoft-iis/(\d+\.\d+)`)
	}

	// CCTV specific
	if strings.Contains(banner, "hikvision") {
		service.Name = "Hikvision Camera"
		service.ExtraInfo["manufacturer"] = "Hikvision"
	} else if strings.Contains(banner, "dahua") {
		service.Name = "Dahua Camera"
		service.ExtraInfo["manufacturer"] = "Dahua"
	} else if strings.Contains(banner, "axis") {
		service.Name = "Axis Camera"
		service.ExtraInfo["manufacturer"] = "Axis"
	}

	// SSH
	if strings.Contains(banner, "ssh") {
		service.Name = "SSH"
		service.Version = extractVersion(banner, `openssh[_-](\d+\.\d+)`)
	}

	// FTP
	if strings.Contains(banner, "ftp") {
		service.Name = "FTP"
	}

	// RTSP
	if strings.Contains(banner, "rtsp") {
		service.Name = "RTSP Stream"
	}
}

// detectHTTPService detects HTTP service details
func (sd *ServiceDetector) detectHTTPService(ip string, port int, service *models.ServiceInfo) {
	url := fmt.Sprintf("http://%s:%d", ip, port)
	
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Extract server header
	if server := resp.Header.Get("Server"); server != "" {
		service.Version = server
		service.ExtraInfo["server"] = server
	}

	// Check for camera-specific headers
	for key, values := range resp.Header {
		key = strings.ToLower(key)
		if strings.Contains(key, "camera") || strings.Contains(key, "hikvision") || 
		   strings.Contains(key, "dahua") || strings.Contains(key, "axis") {
			service.ExtraInfo[key] = strings.Join(values, ", ")
		}
	}

	// Check WWW-Authenticate
	if auth := resp.Header.Get("WWW-Authenticate"); auth != "" {
		service.ExtraInfo["auth_method"] = auth
	}

	service.ExtraInfo["status_code"] = fmt.Sprintf("%d", resp.StatusCode)
}

// detectHTTPSService detects HTTPS service details
func (sd *ServiceDetector) detectHTTPSService(ip string, port int, service *models.ServiceInfo) {
	service.Name = "HTTPS"
	service.ExtraInfo["encrypted"] = "true"
	// Note: Full HTTPS detection requires TLS handling
}

// detectRTSPService detects RTSP service
func (sd *ServiceDetector) detectRTSPService(ip string, port int, service *models.ServiceInfo) {
	service.Name = "RTSP Video Stream"
	service.ExtraInfo["protocol"] = "RTSP"
	
	// Try RTSP OPTIONS request
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	request := "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: CCTV-Scanner\r\n\r\n"
	conn.Write([]byte(request))
	
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	response, _ := reader.ReadString('\n')
	
	if strings.Contains(response, "RTSP") {
		service.Fingerprint = "RTSP/1.0"
	}
}

// detectFTPService detects FTP service
func (sd *ServiceDetector) detectFTPService(ip string, port int, service *models.ServiceInfo) {
	service.Name = "FTP"
	// FTP banner is usually sent automatically
}

// detectSSHService detects SSH service
func (sd *ServiceDetector) detectSSHService(ip string, port int, service *models.ServiceInfo) {
	service.Name = "SSH"
	service.ExtraInfo["protocol"] = "SSH"
}

// detectTelnetService detects Telnet service
func (sd *ServiceDetector) detectTelnetService(ip string, port int, service *models.ServiceInfo) {
	service.Name = "Telnet"
	service.ExtraInfo["protocol"] = "Telnet"
	service.ExtraInfo["warning"] = "Unencrypted protocol"
}

// getProbeForPort returns the appropriate probe for a port
func (sd *ServiceDetector) getProbeForPort(port int) string {
	switch port {
	case 80, 8080, 8000, 8888:
		return "GET / HTTP/1.0\r\n\r\n"
	case 554:
		return "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"
	case 21:
		return "USER anonymous\r\n"
	default:
		return "\r\n"
	}
}

// extractVersion extracts version using regex
func extractVersion(text, pattern string) string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(text)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}