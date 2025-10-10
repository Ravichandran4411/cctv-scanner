package detector

import (
	"github.com/gatiella/cctv-scanner/configs"
	"github.com/gatiella/cctv-scanner/internal/checker"
	"github.com/gatiella/cctv-scanner/pkg/models"
)

// Detector handles device detection and vulnerability checking
type Detector struct {
	config  *configs.Config
	checker *checker.Checker
}

// NewDetector creates a new Detector instance
func NewDetector(config *configs.Config) *Detector {
	return &Detector{
		config:  config,
		checker: checker.NewChecker(config),
	}
}

// DetectDevice performs all detection and checking on a device
func (d *Detector) DetectDevice(device *models.Device) {
	// Check manufacturer and characteristics
	d.checker.CheckManufacturer(device)
	
	// Run security checks
	d.checker.CheckHTTPSecurity(device)
	d.checker.CheckAuthentication(device)
	
	if d.config.CheckDefaultCreds {
		d.checker.CheckDefaultCredentials(device)
	}
	
	d.checker.CheckRTSP(device)
	d.checker.CheckCommonVulnerabilities(device)
}