package models

import (
	"time"
)

// Device represents a network device
type Device struct {
	IP           string          `json:"ip"`
	Port         int             `json:"port"`
	Manufacturer string          `json:"manufacturer"`
	Model        string          `json:"model"`        // Device model
	Firmware     string          `json:"firmware"`     // Firmware version
	Vulnerable   bool            `json:"vulnerable"`
	Issues       []SecurityIssue `json:"issues"`
	ResponseTime int             `json:"response_time"` // in milliseconds
	ScanTime     time.Time       `json:"scan_time"`

	// Port scanning fields
	OpenPorts []PortInfo    `json:"open_ports,omitempty"`
	Services  []ServiceInfo `json:"services,omitempty"`

	// Fingerprinting fields
	OS          string `json:"os,omitempty"`           // Detected OS (Windows, Linux, etc.)
	HostName    string `json:"hostname,omitempty"`     // Hostname from reverse DNS
	MACAddress  string `json:"mac_address,omitempty"`  // MAC address
	Vendor      string `json:"vendor,omitempty"`       // Vendor from MAC lookup
	DeviceType  string `json:"device_type,omitempty"`  // IP Camera, Router, Computer, etc.

	// CVE fields
	CVEs     []CVEInfo `json:"cves,omitempty"`
	CVECount int       `json:"cve_count"`
}

// SecurityIssue represents a security vulnerability
type SecurityIssue struct {
	Type         string `json:"type"`
	Severity     string `json:"severity"` // Critical, High, Medium, Low
	Description  string `json:"description"`
	Remediation  string `json:"remediation"`
}

// PortInfo represents information about an open port
type PortInfo struct {
	Port         int    `json:"port"`
	Protocol     string `json:"protocol"`      // tcp/udp
	State        string `json:"state"`         // open/closed/filtered
	Service      string `json:"service"`       // http, ssh, etc.
	ResponseTime int    `json:"response_time_ms"` // Response time in ms
}

// ServiceInfo represents detected service information
type ServiceInfo struct {
	Port        int               `json:"port"`
	Name        string            `json:"name"`        // Service name (e.g., "Apache HTTP Server")
	Version     string            `json:"version"`     // Service version
	Banner      string            `json:"banner"`      // Service banner
	Fingerprint string            `json:"fingerprint"` // Service fingerprint
	ExtraInfo   map[string]string `json:"extra_info"`  // Additional information
}

// CVEInfo represents a Common Vulnerabilities and Exposures entry
type CVEInfo struct {
	ID                string    `json:"id"`                  // CVE-2021-xxxxx
	Description       string    `json:"description"`         // Vulnerability description
	Severity          string    `json:"severity"`            // Critical/High/Medium/Low
	CVSSScore         float64   `json:"cvss_score"`          // 0.0-10.0
	CVSSVector        string    `json:"cvss_vector"`         // CVSS vector string
	PublishedDate     time.Time `json:"published_date"`      // When CVE was published
	LastModified      time.Time `json:"last_modified"`       // Last modification date
	AffectedVersions  []string  `json:"affected_versions"`   // Affected software versions
	ExploitAvailable  bool      `json:"exploit_available"`   // Public exploit exists
	ExploitMaturity   string    `json:"exploit_maturity"`    // Proof of Concept, Functional, High
	References        []string  `json:"references"`          // Reference URLs
	Remediation       string    `json:"remediation"`         // How to fix
	PatchAvailable    bool      `json:"patch_available"`     // Patch released
}

// Credential represents discovered credentials
type Credential struct {
	IP                    string    `json:"ip"`
	Port                  int       `json:"port"`
	Username              string    `json:"username"`
	Password              string    `json:"password"`
	Protocol              string    `json:"protocol"`
	DiscoveredAt          time.Time `json:"discovered_at"`
	AttemptsBeforeSuccess int       `json:"attempts_before_success"`
}

// NewDevice creates a new Device instance
func NewDevice(ip string, port int) *Device {
	return &Device{
		IP:           ip,
		Port:         port,
		Manufacturer: "Unknown",
		Model:        "",
		Firmware:     "",
		Vulnerable:   false,
		Issues:       []SecurityIssue{},
		OpenPorts:    []PortInfo{},
		Services:     []ServiceInfo{},
		CVEs:         []CVEInfo{},
		ScanTime:     time.Now(),
		DeviceType:   "Unknown Device",
	}
}

// AddIssue adds a security issue to the device
func (d *Device) AddIssue(issueType, severity, description, remediation string) {
	d.Issues = append(d.Issues, SecurityIssue{
		Type:        issueType,
		Severity:    severity,
		Description: description,
		Remediation: remediation,
	})
	d.Vulnerable = true
}

// AddPort adds an open port to the device (accepts PortInfo struct)
func (d *Device) AddPort(portInfo PortInfo) {
	d.OpenPorts = append(d.OpenPorts, portInfo)
}

// AddPortDetails adds an open port with individual parameters
func (d *Device) AddPortDetails(port int, protocol, state, service string, responseTime int) {
	d.OpenPorts = append(d.OpenPorts, PortInfo{
		Port:         port,
		Protocol:     protocol,
		State:        state,
		Service:      service,
		ResponseTime: responseTime,
	})
}

// AddService adds service information
func (d *Device) AddService(service ServiceInfo) {
	d.Services = append(d.Services, service)
}

// AddCVE adds a CVE to the device
func (d *Device) AddCVE(cve CVEInfo) {
	d.CVEs = append(d.CVEs, cve)
	d.CVECount = len(d.CVEs)
	
	// Mark device as vulnerable if CVE is critical or has exploit
	if cve.Severity == "Critical" || cve.CVSSScore >= 9.0 || cve.ExploitAvailable {
		d.Vulnerable = true
	}
}

// GetSeverityScore calculates overall severity score
func (d *Device) GetSeverityScore() int {
	score := 0
	for _, issue := range d.Issues {
		switch issue.Severity {
		case "Critical":
			score += 10
		case "High":
			score += 7
		case "Medium":
			score += 4
		case "Low":
			score += 2
		}
	}
	
	// Add CVE scores
	for _, cve := range d.CVEs {
		score += int(cve.CVSSScore)
	}
	
	return score
}

// HasService checks if device has a specific service
func (d *Device) HasService(serviceName string) bool {
	for _, service := range d.Services {
		if service.Name == serviceName {
			return true
		}
	}
	return false
}

// GetOpenPortCount returns number of open ports
func (d *Device) GetOpenPortCount() int {
	return len(d.OpenPorts)
}

// GetCriticalCVECount returns number of critical CVEs
func (d *Device) GetCriticalCVECount() int {
	count := 0
	for _, cve := range d.CVEs {
		if cve.Severity == "Critical" || cve.CVSSScore >= 9.0 {
			count++
		}
	}
	return count
}

// HasExploitAvailable checks if any CVE has public exploit
func (d *Device) HasExploitAvailable() bool {
	for _, cve := range d.CVEs {
		if cve.ExploitAvailable {
			return true
		}
	}
	return false
}