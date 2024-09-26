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

type Fail2Ban struct {
	MaxFailedAttempts int `json:"max_failed_attempts,omitempty"`
	BanDuration       int `json:"ban_duration,omitempty"`

	failedAttempts map[string]int
	bannedIPs      map[string]time.Time
	four04Attempts map[string]int
	mu             sync.Mutex
	logger         *zap.Logger
}

func (Fail2Ban) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.fail2ban",
		New: func() caddy.Module { return new(Fail2Ban) },
	}
}

func (fb *Fail2Ban) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clientIP := r.RemoteAddr

	if fb.isIPBanned(clientIP) {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return nil
	}

	recorder := caddyhttp.NewResponseRecorder(w, nil, nil)

	err := next.ServeHTTP(recorder, r)

	statusCode := recorder.Status()
	fb.logger.Info("Request processed", zap.String("ip", clientIP), zap.Int("status_code", statusCode))
	if statusCode == http.StatusNotFound {
		fb.register404Attempt(clientIP)
	} else {
		fb.resetFailedAttempts(clientIP)
		fb.reset404Attempts(clientIP)
	}

	return err
}

func (fb *Fail2Ban) register404Attempt(ip string) {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	fb.four04Attempts[ip]++

	if fb.four04Attempts[ip] >= fb.MaxFailedAttempts {
		fb.bannedIPs[ip] = time.Now().Add(time.Duration(fb.BanDuration) * time.Second)
		delete(fb.four04Attempts, ip)

		if fb.logger != nil {
			fb.logger.Info("Banning IP due to too many 404 attempts", zap.String("ip", ip))
		}
	}
}

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

func (fb *Fail2Ban) resetFailedAttempts(ip string) {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	delete(fb.failedAttempts, ip)
}

func (fb *Fail2Ban) reset404Attempts(ip string) {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	delete(fb.four04Attempts, ip)
}

func (fb *Fail2Ban) Provision(ctx caddy.Context) error {
	fb.failedAttempts = make(map[string]int)
	fb.bannedIPs = make(map[string]time.Time)
	fb.four04Attempts = make(map[string]int)

	fb.logger = ctx.Logger()
	fb.logger.Info("Fail2Ban plugin provisioned")
	return nil
}

var (
	_ caddyhttp.MiddlewareHandler = (*Fail2Ban)(nil)
	_ caddy.Provisioner           = (*Fail2Ban)(nil)
)
