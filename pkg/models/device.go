package models

import "time"

// Device represents a detected network device
type Device struct {
	IP           string
	Port         int
	Manufacturer string
	Model        string
	Firmware     string
	Vulnerable   bool
	Issues       []SecurityIssue
	ScanTime     time.Time
	ResponseTime int // in milliseconds

	// Enhanced port scanning fields
	OpenPorts []PortInfo      `json:"open_ports"`
	Services  []ServiceInfo   `json:"services"`
	OS        string          `json:"os,omitempty"`
	HostName  string          `json:"hostname,omitempty"`
	
	// NEW: CVE Database fields
	CVEs      []CVEInfo       `json:"cves"`
	CVECount  int             `json:"cve_count"`
}

// PortInfo represents an open port
type PortInfo struct {
	Port         int    `json:"port"`
	Protocol     string `json:"protocol"`
	State        string `json:"state"`
	Service      string `json:"service"`
	ResponseTime int    `json:"response_time_ms"`
}

// ServiceInfo represents a detected service
type ServiceInfo struct {
	Port        int               `json:"port"`
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Banner      string            `json:"banner"`
	Fingerprint string            `json:"fingerprint"`
	ExtraInfo   map[string]string `json:"extra_info"`
}

// SecurityIssue represents a security vulnerability or concern
type SecurityIssue struct {
	Severity    string
	Type        string
	Description string
	Remediation string
}

// NEW: CVEInfo represents a CVE vulnerability
type CVEInfo struct {
	ID               string    `json:"id"`                 // CVE-2017-7921
	Description      string    `json:"description"`        // Vulnerability description
	Severity         string    `json:"severity"`           // Critical, High, Medium, Low
	CVSSScore        float64   `json:"cvss_score"`         // 9.8
	CVSSVector       string    `json:"cvss_vector"`        // CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
	PublishedDate    time.Time `json:"published_date"`     // When CVE was published
	LastModified     time.Time `json:"last_modified"`      // Last update
	AffectedVersions []string  `json:"affected_versions"`  // Firmware versions affected
	ExploitAvailable bool      `json:"exploit_available"`  // Is exploit publicly available
	ExploitMaturity  string    `json:"exploit_maturity"`   // Proof of Concept, Functional, High
	References       []string  `json:"references"`         // Links to CVE details
	Remediation      string    `json:"remediation"`        // How to fix
	PatchAvailable   bool      `json:"patch_available"`    // Is patch available
}

// NewDevice creates a new Device instance
func NewDevice(ip string, port int) *Device {
	return &Device{
		IP:        ip,
		Port:      port,
		Issues:    make([]SecurityIssue, 0),
		OpenPorts: make([]PortInfo, 0),
		Services:  make([]ServiceInfo, 0),
		CVEs:      make([]CVEInfo, 0),
		ScanTime:  time.Now(),
	}
}

// AddIssue adds a security issue to the device
func (d *Device) AddIssue(severity, issueType, description, remediation string) {
	issue := SecurityIssue{
		Severity:    severity,
		Type:        issueType,
		Description: description,
		Remediation: remediation,
	}
	d.Issues = append(d.Issues, issue)
	d.Vulnerable = true
}

// AddPort adds an open port to the device
func (d *Device) AddPort(portInfo PortInfo) {
	d.OpenPorts = append(d.OpenPorts, portInfo)
}

// AddService adds a service to the device
func (d *Device) AddService(serviceInfo ServiceInfo) {
	d.Services = append(d.Services, serviceInfo)
}

// NEW: AddCVE adds a CVE to the device
func (d *Device) AddCVE(cve CVEInfo) {
	d.CVEs = append(d.CVEs, cve)
	d.CVECount = len(d.CVEs)
	d.Vulnerable = true
}

// GetSeverityScore returns a numeric score based on issues
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
	
	// NEW: Add CVE scores
	for _, cve := range d.CVEs {
		score += int(cve.CVSSScore)
	}
	
	return score
}

// GetOpenPortCount returns the number of open ports
func (d *Device) GetOpenPortCount() int {
	return len(d.OpenPorts)
}

// HasService checks if a specific service is running
func (d *Device) HasService(serviceName string) bool {
	for _, service := range d.Services {
		if service.Name == serviceName {
			return true
		}
	}
	return false
}

// NEW: GetCriticalCVECount returns count of critical CVEs
func (d *Device) GetCriticalCVECount() int {
	count := 0
	for _, cve := range d.CVEs {
		if cve.Severity == "Critical" || cve.CVSSScore >= 9.0 {
			count++
		}
	}
	return count
}

// NEW: HasExploitAvailable checks if any CVE has public exploit
func (d *Device) HasExploitAvailable() bool {
	for _, cve := range d.CVEs {
		if cve.ExploitAvailable {
			return true
		}
	}
	return false
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