package security

import (
	"errors"
	"net"
	"sync"
	"time"
)

// ACL restricts management-plane callers (IPC/loopback API) to an explicit
// allowlist of networks. Default posture is loopback-only.
type ACL struct {
	mu    sync.RWMutex
	nets  []*net.IPNet
	allow func(ip net.IP) bool
}

// NewLoopbackACL returns the default: 127.0.0.0/8 and ::1 only.
func NewLoopbackACL() *ACL {
	must := func(cidr string) *net.IPNet {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		return n
	}
	return &ACL{nets: []*net.IPNet{must("127.0.0.0/8"), must("::1/128")}}
}

// NewACL builds an ACL from explicit CIDRs; empty input means deny-all.
func NewACL(cidrs []string) (*ACL, error) {
	a := &ACL{}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		a.nets = append(a.nets, n)
	}
	return a, nil
}

// Allow reports whether ip may reach the management plane.
func (a *ACL) Allow(ip net.IP) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if ip == nil {
		return false
	}
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// AllowString parses s then applies Allow; unparseable input is denied.
func (a *ACL) AllowString(s string) bool { return a.Allow(net.ParseIP(s)) }

// RateLimiter is a small sliding-window limiter ("max events per window"
// per key) for login/token-validation and expensive management calls.
// Fail-closed helper: callers deny on !Allow during bursts.
type RateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

// NewRateLimiter returns a limiter allowing max events per window per key.
func NewRateLimiter(max int, window time.Duration) (*RateLimiter, error) {
	if max <= 0 || window <= 0 {
		return nil, errors.New("security: invalid rate limit parameters")
	}
	return &RateLimiter{hits: make(map[string][]time.Time), max: max, window: window}, nil
}

// Allow records an event for key and reports whether it is within budget.
func (l *RateLimiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := now.Add(-l.window)
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}
