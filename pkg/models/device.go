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
		IP:       ip,
		Port:     port,
		Issues:   make([]SecurityIssue, 0),
		ScanTime: time.Now(),
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