package api

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gatiella/cctv-scanner/configs"
	"github.com/gatiella/cctv-scanner/internal/scanner"
	"github.com/gatiella/cctv-scanner/internal/websocket"
	"github.com/gatiella/cctv-scanner/pkg/models"
	"github.com/google/uuid"
	"github.com/gatiella/cctv-scanner/internal/bruteforce"
)

type Server struct {
	Config    *configs.Config
	Router    *http.ServeMux
	WSHub     *websocket.Hub
	ScanStore *ScanStore
	BFEngine  *bruteforce.BruteForceEngine // NEW
}

type ScanStore struct {
	mu    sync.RWMutex
	scans map[string]*ScanSession
}

type ScanSession struct {
	ID           string
	NetworkRange string
	Status       string
	Progress     int
	StartTime    time.Time
	EndTime      *time.Time
	Devices      []*models.Device
	Scanner      *scanner.Scanner
}

func NewServer(config *configs.Config) *Server {
	return &Server{
		Config: config,
		Router: http.NewServeMux(),
		WSHub:  websocket.NewHub(),
		ScanStore: &ScanStore{
			scans: make(map[string]*ScanSession),
		},
		BFEngine: bruteforce.NewBruteForceEngine(), // NEW
	}
}
func (s *Server) SetupRoutes() {
	// Start WebSocket hub
	go s.WSHub.Run()

	// Enable CORS for all routes
	s.Router.HandleFunc("/", s.corsMiddleware(s.handleRoot))
	
	// API routes
	s.Router.HandleFunc("/api/health", s.corsMiddleware(s.handleHealth))
	s.Router.HandleFunc("/api/interfaces", s.corsMiddleware(s.handleGetInterfaces))
	s.Router.HandleFunc("/api/scan/start", s.corsMiddleware(s.handleStartScan))
	s.Router.HandleFunc("/api/scan/status/", s.corsMiddleware(s.handleScanStatus))
	s.Router.HandleFunc("/api/scan/results/", s.corsMiddleware(s.handleScanResults))
	s.Router.HandleFunc("/api/scan/history", s.corsMiddleware(s.handleScanHistory))
	s.Router.HandleFunc("/api/ws", s.handleWebSocket)
	// Bruteforce routes
	s.Router.HandleFunc("/api/bruteforce/start", s.corsMiddleware(s.handleBruteForceStart))
	s.Router.HandleFunc("/api/bruteforce/status/", s.corsMiddleware(s.handleBruteForceStatus))
	s.Router.HandleFunc("/api/bruteforce/stop/", s.corsMiddleware(s.handleBruteForceStop))
	s.Router.HandleFunc("/api/bruteforce/results/", s.corsMiddleware(s.handleBruteForceResults))
}

func (s *Server) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next(w, r)
	}
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"message": "CCTV Scanner API",
		"version": "1.0.0",
		"status":  "online",
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
	})
}

func (s *Server) handleGetInterfaces(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	interfaces := scanner.DetectNetworkInterfaces()
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"interfaces": interfaces,
	})
}

func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	var req struct {
		NetworkRange string `json:"network_range"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.NetworkRange == "" {
		http.Error(w, "network_range is required", http.StatusBadRequest)
		return
	}

	// Create scan session
	scanID := uuid.New().String()
	session := &ScanSession{
		ID:           scanID,
		NetworkRange: req.NetworkRange,
		Status:       "running",
		Progress:     0,
		StartTime:    time.Now(),
		Devices:      make([]*models.Device, 0),
		Scanner:      scanner.NewScanner(s.Config),
	}

	s.ScanStore.mu.Lock()
	s.ScanStore.scans[scanID] = session
	s.ScanStore.mu.Unlock()

	// Start scan in background
	go s.performScan(session)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"scan_id": scanID,
		"message": "Scan started",
	})
}

func (s *Server) performScan(session *ScanSession) {
	// Notify start
	s.WSHub.Broadcast(map[string]interface{}{
		"type": "progress",
		"data": map[string]interface{}{
			"scan_id":  session.ID,
			"progress": 0,
			"message":  "Scan started",
		},
	})

	// Perform scan with progress updates
	devices := session.Scanner.ScanNetworkWithProgress(
		session.NetworkRange,
		func(progress int, message string) {
			session.Progress = progress
			s.WSHub.Broadcast(map[string]interface{}{
				"type": "progress",
				"data": map[string]interface{}{
					"scan_id":  session.ID,
					"progress": progress,
					"message":  message,
				},
			})
		},
	)

	// Update session
	endTime := time.Now()
	session.EndTime = &endTime
	session.Status = "completed"
	session.Devices = devices
	session.Progress = 100

	// Notify completion
	s.WSHub.Broadcast(map[string]interface{}{
		"type": "complete",
		"data": map[string]interface{}{
			"scan_id": session.ID,
			"devices": len(devices),
		},
	})
}

func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	scanID := r.URL.Path[len("/api/scan/status/"):]
	
	s.ScanStore.mu.RLock()
	session, exists := s.ScanStore.scans[scanID]
	s.ScanStore.mu.RUnlock()

	if !exists {
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":            session.ID,
		"network_range": session.NetworkRange,
		"status":        session.Status,
		"progress":      session.Progress,
		"start_time":    session.StartTime.Format(time.RFC3339),
		"end_time":      session.EndTime,
	})
}

func (s *Server) handleScanResults(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	scanID := r.URL.Path[len("/api/scan/results/"):]
	
	s.ScanStore.mu.RLock()
	session, exists := s.ScanStore.scans[scanID]
	s.ScanStore.mu.RUnlock()

	if !exists {
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":            session.ID,
		"network_range": session.NetworkRange,
		"status":        session.Status,
		"progress":      session.Progress,
		"start_time":    session.StartTime.Format(time.RFC3339),
		"end_time":      session.EndTime,
		"devices":       session.Devices,
	})
}

func (s *Server) handleScanHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	s.ScanStore.mu.RLock()
	defer s.ScanStore.mu.RUnlock()

	history := make([]map[string]interface{}, 0)
	for _, session := range s.ScanStore.scans {
		vulnerableCount := 0
		for _, device := range session.Devices {
			if device.Vulnerable {
				vulnerableCount++
			}
		}

		history = append(history, map[string]interface{}{
			"id":               session.ID,
			"network_range":    session.NetworkRange,
			"status":           session.Status,
			"start_time":       session.StartTime.Format(time.RFC3339),
			"end_time":         session.EndTime,
			"devices_found":    len(session.Devices),
			"vulnerable_count": vulnerableCount,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"history": history,
	})
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	websocket.ServeWs(s.WSHub, w, r)
}
func (s *Server) handleBruteForceStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	var req bruteforce.AttackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	attackID, err := s.BFEngine.StartAttack(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{
		"attack_id": attackID,
		"message":   "Brute force attack started",
	})
}

func (s *Server) handleBruteForceStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	attackID := r.URL.Path[len("/api/bruteforce/status/"):]
	
	session, err := s.BFEngine.GetStatus(attackID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	statusInfo := session.GetStatusInfo()
	json.NewEncoder(w).Encode(statusInfo)
}
func (s *Server) handleBruteForceStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	
	attackID := r.URL.Path[len("/api/bruteforce/stop/"):]
	
	if err := s.BFEngine.StopAttack(attackID); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Attack stopped successfully",
	})
}

func (s *Server) handleBruteForceResults(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	attackID := r.URL.Path[len("/api/bruteforce/results/"):]
	
	session, err := s.BFEngine.GetStatus(attackID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	credentials, count := session.GetCredentials()
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"credentials": credentials,
		"count":       count,
	})
}