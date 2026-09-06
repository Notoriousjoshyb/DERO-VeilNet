// Per-IP token-bucket rate limiting for authorize + management API.
//
// Limits live here (owned by HardenAgent); the 2-line hooks in
// controller.go Authorize and api.go handleAuthorize call into
// AllowAuthorize / AllowMgmt. Buckets are in-memory only: a restart
// resets them (fail-open to the configured burst, never fail-closed).
// Persistent enforcement is the operator blocklist in abuse.go.
package nodes

import (
	"net"
	"sync"
	"time"
)

// RateLimitConfig tunes the token buckets. Zero values select safe
// defaults. RequestsPerBurst is the bucket capacity; PerWindow is the
// refill interval for one token (sustained rate = 1/PerWindow).
type RateLimitConfig struct {
	// AuthorizeBurst caps authorize attempts per IP per window.
	AuthorizeBurst int
	// AuthorizeWindow bounds the authorize refill interval.
	AuthorizeWindow time.Duration
	// MgmtBurst caps management-API requests per IP per window.
	MgmtBurst int
	// MgmtWindow bounds the management-API refill interval.
	MgmtWindow time.Duration
}

// DefaultRateLimitConfig is conservative: normal clients never notice,
// floods trip quickly (authorize flood -> 429-class, see api.go).
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		AuthorizeBurst:  8,
		AuthorizeWindow: time.Minute,
		MgmtBurst:       60,
		MgmtWindow:      time.Minute,
	}
}

// normalize fills zero fields with defaults.
func (c RateLimitConfig) normalize() RateLimitConfig {
	d := DefaultRateLimitConfig()
	if c.AuthorizeBurst <= 0 {
		c.AuthorizeBurst = d.AuthorizeBurst
	}
	if c.AuthorizeWindow <= 0 {
		c.AuthorizeWindow = d.AuthorizeWindow
	}
	if c.MgmtBurst <= 0 {
		c.MgmtBurst = d.MgmtBurst
	}
	if c.MgmtWindow <= 0 {
		c.MgmtWindow = d.MgmtWindow
	}
	return c
}

// bucket is one token bucket.
type bucket struct {
	tokens float64
	last   time.Time
}

// RateLimiter holds per-IP token buckets for two classes (authorize,
// management API). It is safe for concurrent use.
type RateLimiter struct {
	mu   sync.Mutex
	cfg  RateLimitConfig
	auth map[string]*bucket
	mgmt map[string]*bucket
	now  func() time.Time
}

// NewRateLimiter builds a limiter; nil now uses time.Now.
func NewRateLimiter(cfg RateLimitConfig, now func() time.Time) *RateLimiter {
	if now == nil {
		now = time.Now
	}
	return &RateLimiter{
		cfg:  cfg.normalize(),
		auth: make(map[string]*bucket),
		mgmt: make(map[string]*bucket),
		now:  now,
	}
}

// AllowAuthorize reports whether an authorize attempt from ip may proceed.
func (l *RateLimiter) AllowAuthorize(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.allow(l.auth, ip, l.cfg.AuthorizeBurst, l.cfg.AuthorizeWindow)
}

// AllowMgmt reports whether a management-API request from ip may proceed.
func (l *RateLimiter) AllowMgmt(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.allow(l.mgmt, ip, l.cfg.MgmtBurst, l.cfg.MgmtWindow)
}

// allow consumes one token if available.
func (l *RateLimiter) allow(m map[string]*bucket, ip string, burst int, window time.Duration) bool {
	key := normalizeIP(ip)
	now := l.now()
	b, ok := m[key]
	if !ok {
		b = &bucket{tokens: float64(burst), last: now}
		m[key] = b
	}
	// Refill: one token per window elapsed.
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += float64(elapsed) / float64(window)
		if b.tokens > float64(burst) {
			b.tokens = float64(burst)
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// normalizeIP canonicalizes "" and unparseable input to fixed keys so
// missing addresses share one bucket instead of bypassing limits.
func normalizeIP(ip string) string {
	if ip == "" {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	if parsed := net.ParseIP(ip); parsed != nil {
		return parsed.String()
	}
	return "invalid:" + ip
}
