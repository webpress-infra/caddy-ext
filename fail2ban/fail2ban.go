package fail2ban

import (
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Fail2Ban{})
}

// Fail2Ban struct holds configuration and runtime data
type Fail2Ban struct {
	MaxFailedAttempts int `json:"max_failed_attempts,omitempty"`
	BanDuration       int `json:"ban_duration,omitempty"`

	failedAttempts map[string]int
	bannedIPs      map[string]time.Time
	four04Attempts map[string]int
	mu             sync.Mutex
	logger         *zap.Logger // Logger instance
}

// CaddyModule returns the Caddy module information.
func (Fail2Ban) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.fail2ban",
		New: func() caddy.Module { return new(Fail2Ban) },
	}
}

// ServeHTTP implements the HTTP handler functionality of the plugin
func (fb *Fail2Ban) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clientIP := r.RemoteAddr

	// Check if IP is banned
	if fb.isIPBanned(clientIP) {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return nil
	}

	// Call the next handler in the chain
	err := next.ServeHTTP(w, r)
	fb.logger.Info("Request", zap.String("ip", clientIP), zap.String("status", w.Header().Get("X-Status")))
	// Check for 404 response
	if err == nil && w.Header().Get("X-Status") == "404" {
		fb.register404Attempt(clientIP)
	} else {
		// Reset attempts on successful request
		fb.resetFailedAttempts(clientIP)
		fb.reset404Attempts(clientIP)
	}

	return err
}

// Register a 404 attempt for a given IP
func (fb *Fail2Ban) register404Attempt(ip string) {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	// Increment 404 attempts
	fb.four04Attempts[ip]++

	// If the 404 attempts exceed the maximum allowed, ban the IP
	if fb.four04Attempts[ip] >= fb.MaxFailedAttempts {
		fb.bannedIPs[ip] = time.Now().Add(time.Duration(fb.BanDuration) * time.Second)
		delete(fb.four04Attempts, ip) // Remove from attempts map

		// Log the banning of the IP
		if fb.logger != nil {
			fb.logger.Info("Banning IP due to too many 404 attempts", zap.String("ip", ip))
		}
	}
}

// Check if an IP is currently banned
func (fb *Fail2Ban) isIPBanned(ip string) bool {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	banEndTime, banned := fb.bannedIPs[ip]
	if banned {
		if time.Now().After(banEndTime) {
			delete(fb.bannedIPs, ip)
			return false
		}
		return true
	}
	return false
}

// Reset failed attempts for an IP after a successful request
func (fb *Fail2Ban) resetFailedAttempts(ip string) {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	delete(fb.failedAttempts, ip)
}

// Reset 404 attempts for an IP
func (fb *Fail2Ban) reset404Attempts(ip string) {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	delete(fb.four04Attempts, ip)
}

// Provision sets up the initial state
func (fb *Fail2Ban) Provision(ctx caddy.Context) error {
	// Initialize the maps for tracking attempts and banned IPs
	fb.failedAttempts = make(map[string]int)
	fb.bannedIPs = make(map[string]time.Time)
	fb.four04Attempts = make(map[string]int)

	// Get the logger from Caddy's context
	fb.logger = ctx.Logger() // Get a logger instance for the Fail2Ban handler
	fb.logger.Info("Fail2Ban plugin provisioned")
	return nil
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*Fail2Ban)(nil)
	_ caddy.Provisioner           = (*Fail2Ban)(nil)
)
