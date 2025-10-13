package cve

import (
	"strings"

	"github.com/gatiella/cctv-scanner/pkg/models"
)

// CVEChecker checks devices against CVE database
type CVEChecker struct {
	database *CVEDatabase
}

// NewCVEChecker creates a new CVE checker
func NewCVEChecker() *CVEChecker {
	return &CVEChecker{
		database: NewCVEDatabase(),
	}
}

// CheckDevice checks a device for known CVEs
func (cc *CVEChecker) CheckDevice(device *models.Device) {
	// ✅ FIX: Only check CVEs if manufacturer is IDENTIFIED
	if device.Manufacturer == "" || device.Manufacturer == "Unknown" || device.Manufacturer == "Unknown Device" {
		// Don't add CVEs to unidentified devices
		// Only add an informational note
		device.AddIssue(
			"Unknown Device Detection",
			"Info",
			"Device manufacturer could not be identified. Manual inspection recommended to determine if device is vulnerable.",
			"Perform manual fingerprinting or check device documentation",
		)
		return // ✅ Exit early - no CVEs added
	}

	// Look up CVEs for this IDENTIFIED manufacturer
	cves := cc.database.LookupCVEs(device.Manufacturer)
	
	// ✅ FIX: Don't return generic CVEs for unknown devices
	if len(cves) == 0 {
		return // No CVEs found for this manufacturer
	}
	
	for _, cve := range cves {
		// Add all CVEs for this manufacturer
		// In production, you'd filter by firmware version if known
		device.AddCVE(cve)
		
		// Also add as security issue for compatibility
		cc.addCVEAsIssue(device, cve)
	}
}

// addCVEAsIssue adds CVE as a security issue
func (cc *CVEChecker) addCVEAsIssue(device *models.Device, cve models.CVEInfo) {
	exploitStatus := ""
	if cve.ExploitAvailable {
		exploitStatus = " [EXPLOIT AVAILABLE]"
	}
	
	description := cve.Description + exploitStatus
	if len(cve.AffectedVersions) > 0 {
		description += " Affected versions: " + strings.Join(cve.AffectedVersions, ", ")
	}
	
	device.AddIssue(
		cve.ID,
		cve.Severity,
		description,
		cve.Remediation,
	)
}

// GetDatabaseStats returns statistics about the CVE database
func (cc *CVEChecker) GetDatabaseStats() map[string]interface{} {
	return map[string]interface{}{
		"total_cves":    cc.database.GetCVECount(),
		"manufacturers": len(cc.database.cves),
	}
}