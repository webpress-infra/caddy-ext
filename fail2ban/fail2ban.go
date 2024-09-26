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

var (
	failedAttempts = make(map[string]int)
	bannedIPs      = make(map[string]time.Time)
	four04Attempts = make(map[string]int)
	mu             sync.Mutex
	logger         *zap.Logger
)

type Fail2Ban struct {
	MaxFailedAttempts int `json:"max_failed_attempts,omitempty"`
	BanDuration       int `json:"ban_duration,omitempty"`
}

func (Fail2Ban) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.fail2ban",
		New: func() caddy.Module { return new(Fail2Ban) },
	}
}

func (fb *Fail2Ban) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	clientIP := r.RemoteAddr

	if isIPBanned(clientIP) {
		http.Error(w, "Access Denied", http.StatusForbidden)
		return nil
	}

	recorder := caddyhttp.NewResponseRecorder(w, nil, nil)

	err := next.ServeHTTP(recorder, r)

	statusCode := recorder.Status()
	if statusCode == http.StatusNotFound {
		register404Attempt(clientIP, fb.MaxFailedAttempts, fb.BanDuration)
	} else {
		resetFailedAttempts(clientIP)
		reset404Attempts(clientIP)
	}

	return err
}

func register404Attempt(ip string, maxFailedAttempts, banDuration int) {
	mu.Lock()
	defer mu.Unlock()

	four04Attempts[ip]++

	if four04Attempts[ip] >= maxFailedAttempts {
		bannedIPs[ip] = time.Now().Add(time.Duration(banDuration) * time.Second)
		delete(four04Attempts, ip)

		if logger != nil {
			logger.Info("Banning IP due to too many 404 attempts", zap.String("ip", ip))
		}
	}
}

func isIPBanned(ip string) bool {
	mu.Lock()
	defer mu.Unlock()

	banEndTime, banned := bannedIPs[ip]
	if banned {
		if time.Now().After(banEndTime) {
			delete(bannedIPs, ip)
			return false
		}
		return true
	}
	return false
}

func resetFailedAttempts(ip string) {
	mu.Lock()
	defer mu.Unlock()

	delete(failedAttempts, ip)
}

func reset404Attempts(ip string) {
	mu.Lock()
	defer mu.Unlock()

	delete(four04Attempts, ip)
}

func (fb *Fail2Ban) Provision(ctx caddy.Context) error {
	if logger == nil {
		logger = ctx.Logger()
		logger.Info("Fail2Ban plugin provisioned as singleton")
	}
	return nil
}

var (
	_ caddyhttp.MiddlewareHandler = (*Fail2Ban)(nil)
	_ caddy.Provisioner           = (*Fail2Ban)(nil)
)
