package cve

import (
	"strings"
	"time"

	"github.com/gatiella/cctv-scanner/pkg/models"
)

// CVEDatabase holds the vulnerability database
type CVEDatabase struct {
	cves map[string][]models.CVEInfo // manufacturer -> CVEs
}

// NewCVEDatabase creates and initializes the CVE database
func NewCVEDatabase() *CVEDatabase {
	db := &CVEDatabase{
		cves: make(map[string][]models.CVEInfo),
	}
	db.loadCVEs()
	return db
}

// loadCVEs loads CVE data into memory
func (db *CVEDatabase) loadCVEs() {
	// Hikvision CVEs
	db.cves["hikvision"] = []models.CVEInfo{
		{
			ID:          "CVE-2017-7921",
			Description: "Authentication bypass vulnerability in Hikvision IP cameras. Allows unauthenticated remote attackers to access privileged functions.",
			Severity:    "Critical",
			CVSSScore:   9.8,
			CVSSVector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			PublishedDate: time.Date(2017, 9, 23, 0, 0, 0, 0, time.UTC),
			LastModified:  time.Date(2019, 10, 3, 0, 0, 0, 0, time.UTC),
			AffectedVersions: []string{
				"V5.2.0 build 140721 to V5.4.0 build 160530",
				"V5.2.5 build 141201 to V5.4.4 Build 161125",
			},
			ExploitAvailable: true,
			ExploitMaturity:  "Functional",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2017-7921",
				"https://www.exploit-db.com/exploits/44158",
			},
			Remediation:    "Update firmware to version 5.4.5 or later immediately",
			PatchAvailable: true,
		},
		{
			ID:          "CVE-2021-36260",
			Description: "Command injection vulnerability in Hikvision web servers. Allows remote code execution.",
			Severity:    "Critical",
			CVSSScore:   9.8,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			PublishedDate: time.Date(2021, 9, 18, 0, 0, 0, 0, time.UTC),
			LastModified:  time.Date(2022, 5, 3, 0, 0, 0, 0, time.UTC),
			AffectedVersions: []string{
				"Multiple products and firmware versions",
			},
			ExploitAvailable: true,
			ExploitMaturity:  "Functional",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2021-36260",
				"https://www.hikvision.com/en/support/cybersecurity/security-advisory/",
			},
			Remediation:    "Apply latest security patches from Hikvision",
			PatchAvailable: true,
		},
		{
			ID:          "CVE-2020-25078",
			Description: "Unauthenticated access to configuration files in Hikvision devices.",
			Severity:    "High",
			CVSSScore:   7.5,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			PublishedDate: time.Date(2020, 9, 8, 0, 0, 0, 0, time.UTC),
			LastModified:  time.Date(2020, 9, 15, 0, 0, 0, 0, time.UTC),
			AffectedVersions: []string{
				"Various models V5.x",
			},
			ExploitAvailable: true,
			ExploitMaturity:  "Proof of Concept",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2020-25078",
			},
			Remediation:    "Update to latest firmware version",
			PatchAvailable: true,
		},
	}

	// Dahua CVEs
	db.cves["dahua"] = []models.CVEInfo{
		{
			ID:          "CVE-2021-33044",
			Description: "Authentication bypass vulnerability in Dahua IP cameras allowing unauthorized access.",
			Severity:    "Critical",
			CVSSScore:   9.8,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			PublishedDate: time.Date(2021, 6, 17, 0, 0, 0, 0, time.UTC),
			LastModified:  time.Date(2021, 6, 28, 0, 0, 0, 0, time.UTC),
			AffectedVersions: []string{
				"Multiple products",
			},
			ExploitAvailable: true,
			ExploitMaturity:  "Functional",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2021-33044",
			},
			Remediation:    "Update to latest firmware immediately",
			PatchAvailable: true,
		},
		{
			ID:          "CVE-2020-9529",
			Description: "Remote code execution vulnerability in Dahua devices via crafted requests.",
			Severity:    "Critical",
			CVSSScore:   9.8,
			CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			PublishedDate: time.Date(2020, 3, 5, 0, 0, 0, 0, time.UTC),
			LastModified:  time.Date(2020, 3, 10, 0, 0, 0, 0, time.UTC),
			AffectedVersions: []string{
				"Various firmware versions",
			},
			ExploitAvailable: true,
			ExploitMaturity:  "High",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2020-9529",
			},
			Remediation:    "Apply security patches from vendor",
			PatchAvailable: true,
		},
	}

	// Axis CVEs
	db.cves["axis"] = []models.CVEInfo{
		{
			ID:          "CVE-2018-10660",
			Description: "Buffer overflow vulnerability in Axis cameras allowing remote code execution.",
			Severity:    "High",
			CVSSScore:   8.1,
			CVSSVector:  "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
			PublishedDate: time.Date(2018, 5, 2, 0, 0, 0, 0, time.UTC),
			LastModified:  time.Date(2018, 6, 18, 0, 0, 0, 0, time.UTC),
			AffectedVersions: []string{
				"AXIS OS versions 5.x - 7.x",
			},
			ExploitAvailable: false,
			ExploitMaturity:  "Unproven",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2018-10660",
				"https://www.axis.com/support/firmware-security",
			},
			Remediation:    "Upgrade to AXIS OS 8.x or later",
			PatchAvailable: true,
		},
	}

	// Generic/Multiple Manufacturer CVEs
	db.cves["generic"] = []models.CVEInfo{
		{
			ID:          "CVE-2019-11219",
			Description: "Default credentials vulnerability in multiple IP camera brands.",
			Severity:    "Critical",
			CVSSScore:   9.8,
			CVSSVector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			PublishedDate: time.Date(2019, 4, 15, 0, 0, 0, 0, time.UTC),
			LastModified:  time.Date(2019, 4, 25, 0, 0, 0, 0, time.UTC),
			AffectedVersions: []string{
				"Various manufacturers and models",
			},
			ExploitAvailable: true,
			ExploitMaturity:  "High",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2019-11219",
			},
			Remediation:    "Change default credentials immediately",
			PatchAvailable: false,
		},
	}

	// Foscam CVEs
	db.cves["foscam"] = []models.CVEInfo{
		{
			ID:          "CVE-2018-6830",
			Description: "Remote command execution in Foscam cameras via ONVIF service.",
			Severity:    "Critical",
			CVSSScore:   9.8,
			CVSSVector:  "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			PublishedDate: time.Date(2018, 2, 8, 0, 0, 0, 0, time.UTC),
			LastModified:  time.Date(2018, 3, 13, 0, 0, 0, 0, time.UTC),
			AffectedVersions: []string{
				"Multiple models",
			},
			ExploitAvailable: true,
			ExploitMaturity:  "Functional",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2018-6830",
			},
			Remediation:    "Update firmware and disable ONVIF if not needed",
			PatchAvailable: true,
		},
	}
}

// LookupCVEs finds CVEs for a device based on manufacturer
func (db *CVEDatabase) LookupCVEs(manufacturer string) []models.CVEInfo {
	manufacturer = strings.ToLower(manufacturer)
	
	// Direct match
	if cves, exists := db.cves[manufacturer]; exists {
		return cves
	}
	
	// Fuzzy match
	for key, cves := range db.cves {
		if strings.Contains(manufacturer, key) || strings.Contains(key, manufacturer) {
			return cves
		}
	}
	
	// Return generic CVEs if no match
	return db.cves["generic"]
}

// GetCVEByID retrieves a specific CVE by ID
func (db *CVEDatabase) GetCVEByID(cveID string) *models.CVEInfo {
	for _, cveList := range db.cves {
		for _, cve := range cveList {
			if cve.ID == cveID {
				return &cve
			}
		}
	}
	return nil
}

// GetAllCVEs returns all CVEs in the database
func (db *CVEDatabase) GetAllCVEs() []models.CVEInfo {
	allCVEs := make([]models.CVEInfo, 0)
	for _, cveList := range db.cves {
		allCVEs = append(allCVEs, cveList...)
	}
	return allCVEs
}

// GetCVECount returns total number of CVEs in database
func (db *CVEDatabase) GetCVECount() int {
	count := 0
	for _, cveList := range db.cves {
		count += len(cveList)
	}
	return count
}