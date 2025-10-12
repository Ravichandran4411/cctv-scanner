package bruteforce

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

type Authenticator struct {
	targetIP   string
	targetPort int
	client     *http.Client
}

func NewAuthenticator(ip string, port int) *Authenticator {
	return &Authenticator{
		targetIP:   ip,
		targetPort: port,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (a *Authenticator) TestCredential(username, password, protocol string) (bool, error) {
	switch protocol {
	case "HTTP":
		return a.testHTTP(username, password)
	case "RTSP":
		return a.testRTSP(username, password)
	case "FTP":
		return a.testFTP(username, password)
	default:
		return false, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

func (a *Authenticator) testHTTP(username, password string) (bool, error) {
	url := fmt.Sprintf("http://%s:%d", a.targetIP, a.targetPort)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}

	req.SetBasicAuth(username, password)

	resp, err := a.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// Success if 200 OK or 30x redirect (authenticated)
	return resp.StatusCode == http.StatusOK || 
	       (resp.StatusCode >= 300 && resp.StatusCode < 400), nil
}

func (a *Authenticator) testRTSP(username, password string) (bool, error) {
	// RTSP authentication testing
	// For now, return false (implement if needed)
	return false, nil
}

func (a *Authenticator) testFTP(username, password string) (bool, error) {
	// FTP authentication testing
	// For now, return false (implement if needed)
	return false, nil
}