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
					InsecureSkipVerify: true, // For testing purposes only
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
	
	manufacturers := map[string]string{
		"hikvision": "Hikvision",
		"dahua":     "Dahua",
		"axis":      "Axis Communications",
		"vivotek":   "Vivotek",
		"foscam":    "Foscam",
		"ipcam":     "Generic IP Camera",
		"amcrest":   "Amcrest",
		"reolink":   "Reolink",
		"ubnt":      "Ubiquiti",
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
}

// CheckHTTPSecurity checks for HTTPS usage
func (c *Checker) CheckHTTPSecurity(device *models.Device) {
	if device.Port == 80 || device.Port == 8080 || device.Port == 8000 || device.Port == 8888 {
		device.AddIssue(
			"High",
			"Unencrypted Communication",
			"Device uses HTTP instead of HTTPS, credentials and video may be transmitted in cleartext",
			"Enable HTTPS in device settings and use SSL/TLS certificates",
		)
	}
}

// CheckAuthentication checks authentication requirements
func (c *Checker) CheckAuthentication(device *models.Device) {
	url := fmt.Sprintf("http://%s:%d", device.IP, device.Port)
	
	resp, err := c.client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Check if accessible without authentication
	if resp.StatusCode == 200 {
		device.AddIssue(
			"Critical",
			"No Authentication Required",
			"Web interface is accessible without any authentication",
			"Enable authentication and require strong passwords",
		)
	}
	
	// Check for basic auth over HTTP
	if resp.StatusCode == 401 && device.Port != 443 {
		device.AddIssue(
			"High",
			"Basic Auth over HTTP",
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
	// Check for common vulnerable paths
	vulnerablePaths := []string{
		"/system.ini",
		"/config/config.ini",
		"/../../../etc/passwd",
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
	
	// Hikvision specific checks
	if strings.Contains(strings.ToLower(device.Manufacturer), "hikvision") {
		c.checkHikvisionVulnerabilities(device)
	}
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