package fail2ban

import (
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	// Register the plugin with Caddy
	caddy.RegisterModule(Fail2Ban{})
}

// Fail2Ban struct holds configuration and runtime data
type Fail2Ban struct {
	// Maximum failed attempts before banning the IP (configurable in JSON)
	MaxFailedAttempts int `json:"max_failed_attempts,omitempty"`
	// Ban duration in seconds (configurable in JSON)
	BanDuration int `json:"ban_duration,omitempty"`

	// Runtime data: Maps to track failed attempts and banned IPs
	failedAttempts map[string]int
	bannedIPs      map[string]time.Time
	four04Attempts map[string]int
	mu             sync.Mutex
}

// CaddyModule returns the Caddy module information.
func (Fail2Ban) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.fail2ban",                     // Module ID
		New: func() caddy.Module { return new(Fail2Ban) }, // Instantiate a new Fail2Ban handler
	}
}

// ServeHTTP processes each HTTP request and checks for 404 attempts or bans.
func (fb *Fail2Ban) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clientIP := r.RemoteAddr

	// Check if the IP is already banned
	if fb.isIPBanned(clientIP) {
		// Return 403 Forbidden if banned
		http.Error(w, "Access Denied", http.StatusForbidden)
		return nil
	}

	// Call the next handler in the chain
	err := next.ServeHTTP(w, r)

	// Check if the request resulted in a 404 response
	if err == nil && w.Header().Get("X-Status") == "404" {
		// Register a 404 attempt for this IP
		fb.register404Attempt(clientIP)
	} else {
		// Reset attempts for the IP after a successful request
		fb.resetFailedAttempts(clientIP)
		fb.reset404Attempts(clientIP)
	}

	return err
}

// Register a 404 attempt for a given IP and ban if necessary.
func (fb *Fail2Ban) register404Attempt(ip string) {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	// Increment the number of 404 attempts for this IP
	fb.four04Attempts[ip]++

	// If the number of 404 attempts exceeds MaxFailedAttempts, ban the IP
	if fb.four04Attempts[ip] >= fb.MaxFailedAttempts {
		// Ban the IP by adding it to the bannedIPs map with a ban expiration time
		fb.bannedIPs[ip] = time.Now().Add(time.Duration(fb.BanDuration) * time.Second)
		// Remove the IP from the 404 attempts map
		delete(fb.four04Attempts, ip)
	}
}

// Check if an IP is currently banned by looking it up in the bannedIPs map.
func (fb *Fail2Ban) isIPBanned(ip string) bool {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	// Check if the IP is in the bannedIPs map
	banEndTime, banned := fb.bannedIPs[ip]
	if banned {
		// If the ban duration has expired, unban the IP
		if time.Now().After(banEndTime) {
			delete(fb.bannedIPs, ip)
			return false
		}
		return true
	}
	return false
}

// Reset failed attempts for an IP after a successful request.
func (fb *Fail2Ban) resetFailedAttempts(ip string) {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	// Remove the IP from the failed attempts map
	delete(fb.failedAttempts, ip)
}

// Reset 404 attempts for an IP.
func (fb *Fail2Ban) reset404Attempts(ip string) {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	// Remove the IP from the 404 attempts map
	delete(fb.four04Attempts, ip)
}

// Provision sets up the initial state of the Fail2Ban module.
func (fb *Fail2Ban) Provision(ctx caddy.Context) error {
	// Initialize the maps for tracking attempts and banned IPs
	fb.failedAttempts = make(map[string]int)
	fb.bannedIPs = make(map[string]time.Time)
	fb.four04Attempts = make(map[string]int)
	return nil
}

// Interface guards: Ensure that the Fail2Ban struct implements necessary interfaces
var (
	_ caddyhttp.MiddlewareHandler = (*Fail2Ban)(nil)
	_ caddy.Provisioner           = (*Fail2Ban)(nil)
)
