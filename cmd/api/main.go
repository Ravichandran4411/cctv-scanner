package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"github.com/gatiella/cctv-scanner/configs"
	"github.com/gatiella/cctv-scanner/internal/api"
)

func main() {
	// Get port from environment or default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Get local IP address
	localIP := getLocalIP()

	// Initialize config
	config := configs.NewDefaultConfig()

	// Create API server
	server := api.NewServer(config)

	// Setup routes
	server.SetupRoutes()

	// Print startup information
	printStartupBanner(port, localIP)

	// Start server - listen on all interfaces (0.0.0.0)
	addr := "0.0.0.0:" + port
	log.Printf("🎯 Binding to: %s\n", addr)
	
	if err := http.ListenAndServe(addr, server.Router); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "unknown"
}

func printStartupBanner(port string, localIP string) {
	banner := `
╔═══════════════════════════════════════════════════════╗
║         CCTV Scanner API Server v1.0                  ║
║              Backend for Mobile App                   ║
╚═══════════════════════════════════════════════════════╝
`
	log.Println(banner)
	log.Printf("🚀 Server starting on port %s\n", port)
	log.Printf("🎯 Binding to: 0.0.0.0:%s (all interfaces)\n", port)
	log.Printf("📱 Your computer's IP: %s\n", localIP)
	log.Println("\n📡 Connection Options:")
	log.Printf("   • Direct IP: http://%s:%s/api\n", localIP, port)
	log.Printf("   • Localhost: http://localhost:%s/api (with adb reverse)\n", port)
	log.Printf("   • WebSocket: ws://%s:%s/api/ws\n", localIP, port)
	log.Println("\n📋 Available Endpoints:")
	log.Println("   GET  /api/health          - Health check")
	log.Println("   GET  /api/interfaces      - Get network interfaces")
	log.Println("   POST /api/scan/start      - Start new scan")
	log.Println("   GET  /api/scan/status/:id - Get scan status")
	log.Println("   GET  /api/scan/results/:id - Get scan results")
	log.Println("   GET  /api/scan/history    - Get scan history")
	log.Println("   WS   /api/ws              - WebSocket connection")
	log.Println("\n💡 Using ADB reverse? Use http://localhost:8080 in Flutter app")
	log.Println("   Run: adb reverse tcp:8080 tcp:8080")
	log.Println("\n✅ Server is ready to accept connections!")
	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
}