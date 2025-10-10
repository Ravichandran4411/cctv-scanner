package configs

import "time"

// Config holds scanner configuration
type Config struct {
	// Scan settings
	Timeout         time.Duration
	MaxConcurrent   int
	CCTVPorts       []int
	
	// Credential check settings
	CheckDefaultCreds bool
	DefaultCreds      map[string][]string
	
	// Detection settings
	Manufacturers []string
}

// NewDefaultConfig returns a config with sensible defaults
func NewDefaultConfig() *Config {
	return &Config{
		Timeout:           3 * time.Second,
		MaxConcurrent:     50,
		CheckDefaultCreds: true,
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
		DefaultCreds: map[string][]string{
			"admin":     {"admin", "12345", "password", "", "1234"},
			"root":      {"root", "12345", "pass", "admin", "password"},
			"user":      {"user", "12345", "password"},
			"service":   {"service", "service"},
			"supervisor": {"supervisor", "supervisor"},
		},
		Manufacturers: []string{
			"hikvision", "dahua", "axis", "vivotek", 
			"foscam", "amcrest", "lorex", "swann",
			"reolink", "ubiquiti", "arlo", "nest",
		},
	}
}