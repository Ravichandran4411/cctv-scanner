package configs

import "time"

// Config holds scanner configuration
type Config struct {
	// Scan settings
	Timeout         time.Duration
	MaxConcurrent   int
	CCTVPorts       []int
	
	// NEW: Port scanning settings
	EnableFullPortScan    bool
	PortScanTimeout       time.Duration
	CommonPorts           []int
	FullPortRange         bool // Scan all 65535 ports
	ServiceDetection      bool
	BannerGrabbing        bool
	OSDetection           bool
	
	// Credential check settings
	CheckDefaultCreds bool
	DefaultCreds      map[string][]string
	
	// Detection settings
	Manufacturers []string

	//new cve checking
	EnableCVECheck bool
}

// NewDefaultConfig returns a config with sensible defaults
func NewDefaultConfig() *Config {
	return &Config{
		Timeout:           3 * time.Second,
		MaxConcurrent:     50,
		CheckDefaultCreds: true,

		//cve checking
		EnableCVECheck: true, 
		
		// NEW: Port scanning defaults
		EnableFullPortScan:    true,
		PortScanTimeout:       2 * time.Second,
		FullPortRange:         false, // Default to common ports only
		ServiceDetection:      true,
		BannerGrabbing:        true,
		OSDetection:           false, // Can be slow
		
		CCTVPorts: []int{
			80,    // HTTP
			443,   // HTTPS
			554,   // RTSP
			8000,  // Common alternate HTTP
			8080,  // Common alternate HTTP
			8888,  // Common alternate HTTP
			37777, // Dahua
			34567, // Dahua DVR
			9000,  // Various cameras
		},
		
		// NEW: Common ports for quick scan (top 100)
		CommonPorts: []int{
			21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
			143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
			// CCTV specific
			554, 8000, 8080, 8888, 37777, 34567, 9000, 10554,
			// Additional common
			20, 69, 123, 137, 138, 161, 162, 389, 636, 1433,
			1521, 3690, 5432, 5631, 5632, 5800, 5901, 6000, 6001, 8008,
			8081, 8443, 8888, 9100, 10000, 32768, 49152, 49153, 49154, 49155,
		},
		
		DefaultCreds: map[string][]string{
			"admin":      {"admin", "12345", "password", "", "1234"},
			"root":       {"root", "12345", "pass", "admin", "password"},
			"user":       {"user", "12345", "password"},
			"service":    {"service", "service"},
			"supervisor": {"supervisor", "supervisor"},
		},
		
		Manufacturers: []string{
			"hikvision", "dahua", "axis", "vivotek",
			"foscam", "amcrest", "lorex", "swann",
			"reolink", "ubiquiti", "arlo", "nest",
		},
	}
}

// GetPortsToScan returns the list of ports to scan based on config
func (c *Config) GetPortsToScan() []int {
	if c.FullPortRange {
		// Return all ports 1-65535 (be careful with this!)
		ports := make([]int, 65535)
		for i := 0; i < 65535; i++ {
			ports[i] = i + 1
		}
		return ports
	}
	
	if c.EnableFullPortScan {
		// Return common ports
		return c.CommonPorts
	}
	
	// Return only CCTV ports
	return c.CCTVPorts
}