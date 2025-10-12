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
	
	// NEW: Enhanced port scanning fields
	OpenPorts    []PortInfo      `json:"open_ports"`
	Services     []ServiceInfo   `json:"services"`
	OS           string          `json:"os,omitempty"`
	HostName     string          `json:"hostname,omitempty"`
}

// NEW: PortInfo represents an open port
type PortInfo struct {
	Port         int    `json:"port"`
	Protocol     string `json:"protocol"` // tcp, udp
	State        string `json:"state"`    // open, closed, filtered
	Service      string `json:"service"`  // http, ssh, ftp, etc.
	ResponseTime int    `json:"response_time_ms"`
}

// NEW: ServiceInfo represents a detected service
type ServiceInfo struct {
	Port        int               `json:"port"`
	Name        string            `json:"name"`        // HTTP, SSH, FTP, RTSP
	Version     string            `json:"version"`     // Apache/2.4.41
	Banner      string            `json:"banner"`      // Server response
	Fingerprint string            `json:"fingerprint"` // Service signature
	ExtraInfo   map[string]string `json:"extra_info"`  // Additional details
}

// SecurityIssue represents a security vulnerability or concern
type SecurityIssue struct {
	Severity    string // Critical, High, Medium, Low
	Type        string // e.g., "Default Credentials", "Unencrypted"
	Description string
	Remediation string
}

// NewDevice creates a new Device instance
func NewDevice(ip string, port int) *Device {
	return &Device{
		IP:           ip,
		Port:         port,
		Issues:       make([]SecurityIssue, 0),
		OpenPorts:    make([]PortInfo, 0),
		Services:     make([]ServiceInfo, 0),
		ScanTime:     time.Now(),
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

// NEW: AddPort adds an open port to the device
func (d *Device) AddPort(portInfo PortInfo) {
	d.OpenPorts = append(d.OpenPorts, portInfo)
}

// NEW: AddService adds a service to the device
func (d *Device) AddService(serviceInfo ServiceInfo) {
	d.Services = append(d.Services, serviceInfo)
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
	return score
}

// NEW: GetOpenPortCount returns the number of open ports
func (d *Device) GetOpenPortCount() int {
	return len(d.OpenPorts)
}

// NEW: HasService checks if a specific service is running
func (d *Device) HasService(serviceName string) bool {
	for _, service := range d.Services {
		if service.Name == serviceName {
			return true
		}
	}
	return false
}