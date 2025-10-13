package reporter

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gatiella/cctv-scanner/pkg/models"
)

// Reporter handles report generation
type Reporter struct{}

// NewReporter creates a new Reporter instance
func NewReporter() *Reporter {
	return &Reporter{}
}

// GenerateReport generates and prints a comprehensive report
func (r *Reporter) GenerateReport(devices []*models.Device) {
	if len(devices) == 0 {
		fmt.Println("\n✅ No devices found on the network.")
		return
	}

	// Sort devices by severity score (highest first)
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].GetSeverityScore() > devices[j].GetSeverityScore()
	})

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("                    NETWORK SCAN RESULTS")
	fmt.Println(strings.Repeat("=", 70))

	for i, device := range devices {
		r.printDeviceReport(i+1, device)
	}

	r.printSummary(devices)
	r.printRecommendations(devices)
}

func (r *Reporter) printDeviceReport(num int, device *models.Device) {
	// Determine device emoji based on type/manufacturer
	emoji := r.getDeviceEmoji(device)
	
	fmt.Printf("\n[%d] %s DEVICE: %s:%d\n", num, emoji, device.IP, device.Port)
	fmt.Println(strings.Repeat("-", 70))
	
	if device.Manufacturer != "" {
		fmt.Printf("    Type: %s\n", device.Manufacturer)
	} else {
		fmt.Printf("    Type: Unknown Device\n")
	}
	
	// Show all open ports if available
	if len(device.OpenPorts) > 0 {
		fmt.Printf("    Open Ports: %v\n", device.OpenPorts)
	}
	
	// Show detected services if available
	if len(device.Services) > 0 {
		fmt.Printf("    Services: ")
		services := []string{}
		for _, service := range device.Services {
			services = append(services, service.Name)
		}
		fmt.Printf("%s\n", strings.Join(services, ", "))
	}
	
	fmt.Printf("    Response Time: %dms\n", device.ResponseTime)
	fmt.Printf("    Scan Time: %s\n", device.ScanTime.Format("2006-01-02 15:04:05"))

	if !device.Vulnerable {
		fmt.Println("    Status: ✅ No obvious vulnerabilities detected")
		return
	}

	// Print issues grouped by severity
	fmt.Printf("    Security Score: %d (Higher = More Severe)\n", device.GetSeverityScore())
	fmt.Println("\n    🔴 SECURITY ISSUES:")
	
	// Group issues by severity
	severityOrder := []string{"Critical", "High", "Medium", "Low"}
	for _, severity := range severityOrder {
		issues := r.getIssuesBySeverity(device, severity)
		if len(issues) == 0 {
			continue
		}
		
		emoji := r.getSeverityEmoji(severity)
		for _, issue := range issues {
			fmt.Printf("\n    %s [%s] %s\n", emoji, severity, issue.Type)
			fmt.Printf("       Description: %s\n", issue.Description)
			fmt.Printf("       Fix: %s\n", issue.Remediation)
		}
	}
}

func (r *Reporter) getDeviceEmoji(device *models.Device) string {
	manufacturer := strings.ToLower(device.Manufacturer)
	
	// CCTV cameras
	if strings.Contains(manufacturer, "hikvision") || 
	   strings.Contains(manufacturer, "dahua") || 
	   strings.Contains(manufacturer, "axis") ||
	   strings.Contains(manufacturer, "camera") ||
	   strings.Contains(manufacturer, "cctv") {
		return "📹"
	}
	
	// Routers/Network devices
	if strings.Contains(manufacturer, "router") || 
	   strings.Contains(manufacturer, "cisco") ||
	   strings.Contains(manufacturer, "mikrotik") ||
	   strings.Contains(manufacturer, "ubiquiti") {
		return "🌐"
	}
	
	// Printers
	if strings.Contains(manufacturer, "printer") || 
	   strings.Contains(manufacturer, "hp") ||
	   strings.Contains(manufacturer, "epson") {
		return "🖨️"
	}
	
	// Computers/Servers
	if strings.Contains(manufacturer, "windows") || 
	   strings.Contains(manufacturer, "linux") ||
	   strings.Contains(manufacturer, "server") ||
	   strings.Contains(manufacturer, "computer") {
		return "💻"
	}
	
	// NAS/Storage
	if strings.Contains(manufacturer, "nas") || 
	   strings.Contains(manufacturer, "synology") ||
	   strings.Contains(manufacturer, "qnap") {
		return "💾"
	}
	
	// Smart devices/IoT
	if strings.Contains(manufacturer, "iot") || 
	   strings.Contains(manufacturer, "smart") {
		return "🏠"
	}
	
	// Default for unknown devices
	return "📡"
}

func (r *Reporter) getIssuesBySeverity(device *models.Device, severity string) []models.SecurityIssue {
	var issues []models.SecurityIssue
	for _, issue := range device.Issues {
		if issue.Severity == severity {
			issues = append(issues, issue)
		}
	}
	return issues
}

func (r *Reporter) getSeverityEmoji(severity string) string {
	switch severity {
	case "Critical":
		return "🔴"
	case "High":
		return "🟠"
	case "Medium":
		return "🟡"
	case "Low":
		return "🟢"
	default:
		return "⚪"
	}
}

func (r *Reporter) printSummary(devices []*models.Device) {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("                    SUMMARY")
	fmt.Println(strings.Repeat("=", 70))

	vulnerable := 0
	criticalIssues := 0
	highIssues := 0
	mediumIssues := 0
	lowIssues := 0
	
	// Count device types
	deviceTypes := make(map[string]int)

	for _, device := range devices {
		if device.Vulnerable {
			vulnerable++
		}
		for _, issue := range device.Issues {
			switch issue.Severity {
			case "Critical":
				criticalIssues++
			case "High":
				highIssues++
			case "Medium":
				mediumIssues++
			case "Low":
				lowIssues++
			}
		}
		
		// Count device types
		emoji := r.getDeviceEmoji(device)
		deviceTypes[emoji]++
	}

	fmt.Printf("\n📊 Total Devices Found: %d\n", len(devices))
	
	// Show device breakdown
	if len(deviceTypes) > 0 {
		fmt.Println("\n📱 Device Breakdown:")
		for emoji, count := range deviceTypes {
			fmt.Printf("   %s %d devices\n", emoji, count)
		}
	}
	
	fmt.Printf("\n⚠️  Devices with Vulnerabilities: %d", vulnerable)
	if len(devices) > 0 {
		fmt.Printf(" (%.1f%%)", float64(vulnerable)/float64(len(devices))*100)
	}
	fmt.Println()
	
	fmt.Printf("\n🔴 Critical Issues: %d\n", criticalIssues)
	fmt.Printf("🟠 High Issues: %d\n", highIssues)
	fmt.Printf("🟡 Medium Issues: %d\n", mediumIssues)
	fmt.Printf("🟢 Low Issues: %d\n", lowIssues)
}

func (r *Reporter) printRecommendations(devices []*models.Device) {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("                    RECOMMENDATIONS")
	fmt.Println(strings.Repeat("=", 70))
	
	recommendations := []string{
		"🔐 Change ALL default passwords to strong, unique passwords",
		"🔒 Enable HTTPS/SSL for all web interfaces where possible",
		"🔄 Update firmware/software to the latest version on all devices",
		"🌐 Isolate IoT devices on a separate VLAN with restricted access",
		"🚫 Disable UPnP on routers and unnecessary devices",
		"🔑 Implement strong authentication (WPA3, MFA where supported)",
		"🛡️ Use VPN for remote access instead of port forwarding",
		"📹 Disable unnecessary services and close unused ports",
		"🔥 Configure firewall rules to restrict device communication",
		"📝 Perform regular security audits and monitoring",
		"💾 Keep backups of critical device configurations",
	}

	fmt.Println()
	for _, rec := range recommendations {
		fmt.Printf("  • %s\n", rec)
	}
	
	hasDefaultCreds := false
	for _, device := range devices {
		for _, issue := range device.Issues {
			if issue.Type == "Default Credentials" {
				hasDefaultCreds = true
				break
			}
		}
		if hasDefaultCreds {
			break
		}
	}
	
	if hasDefaultCreds {
		fmt.Println("\n⚠️  URGENT: Devices with default credentials detected!")
		fmt.Println("   These devices are at CRITICAL risk and should be secured immediately.")
	}
}

// SaveToFile saves the report to a text file
func (r *Reporter) SaveToFile(devices []*models.Device) string {
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("network_scan_report_%s.txt", timestamp)
	
	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("❌ Error creating file: %v\n", err)
		return ""
	}
	defer file.Close()

	// Redirect output to file
	oldStdout := os.Stdout
	os.Stdout = file

	r.GenerateReport(devices)

	// Restore stdout
	os.Stdout = oldStdout

	return filename
}