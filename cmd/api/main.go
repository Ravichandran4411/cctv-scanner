package main

import (
	"log"
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

	// Initialize config
	config := configs.NewDefaultConfig()

	// Create API server
	server := api.NewServer(config)

	// Setup routes
	server.SetupRoutes()

	// Print startup information
	printStartupBanner(port)

	// Start server
	if err := http.ListenAndServe(":"+port, server.Router); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

func printStartupBanner(port string) {
	banner := `
╔═══════════════════════════════════════════════════════╗
║         CCTV Scanner API Server v1.0                  ║
║              Backend for Mobile App                   ║
╚═══════════════════════════════════════════════════════╝
`
	log.Println(banner)
	log.Printf("🚀 Server starting on port %s\n", port)
	log.Printf("📡 API Base URL: http://localhost:%s/api\n", port)
	log.Printf("🔌 WebSocket URL: ws://localhost:%s/api/ws\n", port)
	log.Println("\n📋 Available Endpoints:")
	log.Println("   GET  /api/health          - Health check")
	log.Println("   GET  /api/interfaces      - Get network interfaces")
	log.Println("   POST /api/scan/start      - Start new scan")
	log.Println("   GET  /api/scan/status/:id - Get scan status")
	log.Println("   GET  /api/scan/results/:id - Get scan results")
	log.Println("   GET  /api/scan/history    - Get scan history")
	log.Println("   WS   /api/ws              - WebSocket connection")
	log.Println("\n✅ Server is ready to accept connections!")
	log.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
}
