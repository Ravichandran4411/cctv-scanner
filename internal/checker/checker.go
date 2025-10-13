package checker

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gatiella/cctv-scanner/configs"
	"github.com/gatiella/cctv-scanner/pkg/models"
)

// Checker performs various security checks
type Checker struct {
	config *configs.Config
	client *http.Client
}

// NewChecker creates a new Checker instance
func NewChecker(config *configs.Config) *Checker {
	return &Checker{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// CheckManufacturer attempts to identify the device manufacturer
func (c *Checker) CheckManufacturer(device *models.Device) {
	url := fmt.Sprintf("http://%s:%d", device.IP, device.Port)
	
	start := time.Now()
	resp, err := c.client.Get(url)
	device.ResponseTime = int(time.Since(start).Milliseconds())
	
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Check Server header
	server := strings.ToLower(resp.Header.Get("Server"))
	
	// Extended manufacturers map - ALL device types
	manufacturers := map[string]string{
		// Cameras
		"hikvision": "Hikvision Camera",
		"dahua":     "Dahua Camera",
		"axis":      "Axis Communications Camera",
		"vivotek":   "Vivotek Camera",
		"foscam":    "Foscam Camera",
		"ipcam":     "Generic IP Camera",
		"amcrest":   "Amcrest Camera",
		"reolink":   "Reolink Camera",
		"ubnt":      "Ubiquiti Camera",
		
		// Routers & Networking
		"cisco":     "Cisco Router/Switch",
		"mikrotik":  "MikroTik Router",
		"tp-link":   "TP-Link Router",
		"tplink":    "TP-Link Router",
		"netgear":   "Netgear Router",
		"linksys":   "Linksys Router",
		"asus":      "ASUS Router",
		"d-link":    "D-Link Router",
		"dlink":     "D-Link Router",
		"huawei":    "Huawei Router",
		"xiaomi":    "Xiaomi Router",
		"openwrt":   "OpenWRT Router",
		
		// Printers
		"hp":        "HP Printer",
		"canon":     "Canon Printer",
		"epson":     "Epson Printer",
		"brother":   "Brother Printer",
		"lexmark":   "Lexmark Printer",
		"xerox":     "Xerox Printer",
		
		// NAS & Storage
		"synology":  "Synology NAS",
		"qnap":      "QNAP NAS",
		"buffalo":   "Buffalo NAS",
		"wd":        "Western Digital NAS",
		"seagate":   "Seagate NAS",
		
		// Web Servers
		"apache":    "Apache Web Server",
		"nginx":     "Nginx Web Server",
		"iis":       "Microsoft IIS Server",
		"lighttpd":  "Lighttpd Server",
		"tomcat":    "Apache Tomcat Server",
		
		// IoT Devices
		"raspberry": "Raspberry Pi",
		"arduino":   "Arduino Device",
		"esp8266":   "ESP8266 IoT Device",
		"esp32":     "ESP32 IoT Device",
		"sonos":     "Sonos Speaker",
		"philips":   "Philips Hue",
		"nest":      "Google Nest Device",
		"alexa":     "Amazon Alexa",
		
		// Other
		"windows":   "Windows Device",
		"linux":     "Linux Server",
		"ubuntu":    "Ubuntu Server",
		"debian":    "Debian Server",
		"centos":    "CentOS Server",
	}

	for key, name := range manufacturers {
		if strings.Contains(server, key) {
			device.Manufacturer = name
			return
		}
	}
	
	// Check WWW-Authenticate header
	wwwAuth := strings.ToLower(resp.Header.Get("WWW-Authenticate"))
	for key, name := range manufacturers {
		if strings.Contains(wwwAuth, key) {
			device.Manufacturer = name
			return
		}
	}
	
	// Check X-Powered-By header
	poweredBy := strings.ToLower(resp.Header.Get("X-Powered-By"))
	if strings.Contains(poweredBy, "php") {
		device.Manufacturer = "PHP Web Application"
	} else if strings.Contains(poweredBy, "express") {
		device.Manufacturer = "Express.js Server"
	} else if strings.Contains(poweredBy, "asp.net") {
		device.Manufacturer = "ASP.NET Application"
	}
}

// CheckHTTPSecurity checks for HTTPS usage
func (c *Checker) CheckHTTPSecurity(device *models.Device) {
	if device.Port == 80 || device.Port == 8080 || device.Port == 8000 || device.Port == 8888 {
		device.AddIssue(
			"High",
			"Unencrypted Communication",
			"Device uses HTTP instead of HTTPS, credentials and data may be transmitted in cleartext",
			"Enable HTTPS in device settings and use SSL/TLS certificates",
		)
	}
}

// CheckAuthentication checks authentication requirements
func (c *Checker) CheckAuthentication(device *models.Device) {
	// ✅ FIX: Skip auth check if device is unknown
	if device.Manufacturer == "Unknown" || device.Manufacturer == "" {
		return
	}
	
	url := fmt.Sprintf("http://%s:%d", device.IP, device.Port)
	
	resp, err := c.client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Check if accessible without authentication
	if resp.StatusCode == 200 {
		device.AddIssue(
			"No Authentication Required",
			"Critical",
			"Web interface is accessible without any authentication",
			"Enable authentication and require strong passwords",
		)
	}
	
	// Check for basic auth over HTTP
	if resp.StatusCode == 401 && device.Port != 443 {
		device.AddIssue(
			"Basic Auth over HTTP",
			"High",
			"Using Basic Authentication over unencrypted HTTP connection",
			"Switch to HTTPS or use digest authentication",
		)
	}
}

// CheckDefaultCredentials checks for common default credentials
func (c *Checker) CheckDefaultCredentials(device *models.Device) {
	url := fmt.Sprintf("http://%s:%d", device.IP, device.Port)
	
	for username, passwords := range c.config.DefaultCreds {
		for _, password := range passwords {
			req, _ := http.NewRequest("GET", url, nil)
			req.SetBasicAuth(username, password)
			
			resp, err := c.client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == 200 {
				credDisplay := fmt.Sprintf("%s:%s", username, password)
				if password == "" {
					credDisplay = fmt.Sprintf("%s:(empty)", username)
				}
				
				device.AddIssue(
					"Critical",
					"Default Credentials",
					fmt.Sprintf("Device accessible with default credentials: %s", credDisplay),
					"Change default password immediately to a strong, unique password",
				)
				return
			}
		}
	}
}

// CheckRTSP checks RTSP stream security
func (c *Checker) CheckRTSP(device *models.Device) {
	if device.Port == 554 {
		device.AddIssue(
			"Medium",
			"RTSP Port Open",
			"RTSP streaming port is accessible. Verify authentication is enabled",
			"Ensure RTSP requires authentication and consider using RTSPS (RTSP over TLS)",
		)
	}
}

// CheckCommonVulnerabilities checks for well-known vulnerabilities
func (c *Checker) CheckCommonVulnerabilities(device *models.Device) {
	// ✅ FIX: Skip vulnerability checks if device is unidentified
	if device.Manufacturer == "Unknown" || device.Manufacturer == "" {
		return // Don't check paths on unknown devices
	}
	vulnerablePaths := []string{
		"/system.ini",
		"/config/config.ini",
		"/../../../etc/passwd",
		"/admin/",
		"/phpmyadmin/",
		"/.env",
		"/config.php",
		"/wp-config.php",
	}
	
	
	baseURL := fmt.Sprintf("http://%s:%d", device.IP, device.Port)
	
	for _, path := range vulnerablePaths {
		req, _ := http.NewRequest("GET", baseURL+path, nil)
		resp, err := c.client.Do(req)
		
		if err != nil {
			continue
		}
		resp.Body.Close()
		
		if resp.StatusCode == 200 {
			device.AddIssue(
				"Critical",
				"Information Disclosure",
				fmt.Sprintf("Sensitive path accessible: %s", path),
				"Update firmware immediately and restrict access to configuration files",
			)
		}
	}
	
	// Check for specific device vulnerabilities
	if strings.Contains(strings.ToLower(device.Manufacturer), "hikvision") {
		c.checkHikvisionVulnerabilities(device)
	}
	
	// Check for common IoT vulnerabilities
	c.checkIoTVulnerabilities(device)
}

func (c *Checker) checkHikvisionVulnerabilities(device *models.Device) {
	// Check for CVE-2017-7921 (Authentication Bypass)
	url := fmt.Sprintf("http://%s:%d/Security/users?auth=YWRtaW46MTEK", device.IP, device.Port)
	resp, err := c.client.Get(url)
	
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			device.AddIssue(
				"Critical",
				"Known Vulnerability CVE-2017-7921",
				"Device vulnerable to authentication bypass attack",
				"Update firmware immediately to latest version",
			)
		}
	}
}

func (c *Checker) checkIoTVulnerabilities(device *models.Device) {
	// Check for Telnet (insecure protocol)
	if device.Port == 23 {
		device.AddIssue(
			"High",
			"Telnet Service Running",
			"Telnet transmits data in plaintext including passwords",
			"Disable Telnet and use SSH instead",
		)
	}
	
	// Check for FTP
	if device.Port == 21 {
		device.AddIssue(
			"Medium",
			"FTP Service Running",
			"FTP transmits data including credentials in plaintext",
			"Use SFTP or FTPS for secure file transfer",
		)
	}
	
	// Check for SMB
	if device.Port == 445 || device.Port == 139 {
		device.AddIssue(
			"High",
			"SMB Service Exposed",
			"SMB service exposed to network, vulnerable to EternalBlue and other exploits",
			"Restrict SMB access and ensure latest patches are applied",
		)
	}
}