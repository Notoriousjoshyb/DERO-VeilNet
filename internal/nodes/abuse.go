// Operator abuse tooling: blocklist, complaint log, key rotation
// helpers, and the emergency-disable auto-trigger.
//
// Privacy rule (binding): the complaint log records reporter,
// timestamp, reason, and action ONLY. It NEVER records traffic
// content, DNS names, URLs, or byte counters.
//
// Persistence: blocklist + policy live in blocklist.json under the
// node dir (DefaultDir); complaints append to complaints.jsonl.
// Both survive restarts; rate-limit buckets (ratelimit.go) do not.
package nodes

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Abuse errors returned by the Authorize precheck hook.
var (
	// ErrBlocked is returned for blocklisted IPs/pubkeys (429-class).
	ErrBlocked = errors.New("nodes: peer is blocklisted")
	// ErrRateLimited is returned when the per-IP bucket is empty (429-class).
	ErrRateLimited = errors.New("nodes: rate limit exceeded, retry later")
)

// AbusePolicy configures the emergency-disable auto-trigger.
// Default (zero) policy disables the trigger: the operator must opt
// in explicitly. Every trigger is logged via the event publisher.
type AbusePolicy struct {
	// AutoDisable turns the threshold trigger on. Default false.
	AutoDisable bool `json:"auto_disable"`
	// ComplaintThreshold fires after this many complaints. <=0 selects
	// DefaultComplaintThreshold when AutoDisable is on.
	ComplaintThreshold int `json:"complaint_threshold"`
}

// DefaultComplaintThreshold is the trigger count when the operator
// enables AutoDisable without a custom threshold.
const DefaultComplaintThreshold = 5

// normalize fills defaults.
func (p AbusePolicy) normalize() AbusePolicy {
	if p.ComplaintThreshold <= 0 {
		p.ComplaintThreshold = DefaultComplaintThreshold
	}
	return p
}

// AbusePolicyPath returns the default policy file path.
func AbusePolicyPath() string { return filepath.Join(DefaultDir(), "abuse.json") }

// LoadAbusePolicy reads path ("" = default); missing file returns the
// zero policy (trigger off).
func LoadAbusePolicy(path string) (AbusePolicy, error) {
	if path == "" {
		path = AbusePolicyPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return AbusePolicy{}, nil
		}
		return AbusePolicy{}, fmt.Errorf("nodes: read abuse policy: %w", err)
	}
	var p AbusePolicy
	if err := json.Unmarshal(data, &p); err != nil {
		return AbusePolicy{}, fmt.Errorf("nodes: corrupt abuse policy %s: %w", path, err)
	}
	return p, nil
}

// SaveAbusePolicy persists the policy with 0600 permissions.
func SaveAbusePolicy(path string, p AbusePolicy) error {
	if path == "" {
		path = AbusePolicyPath()
	}
	data, err := json.MarshalIndent(p.normalize(), "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" {
		_ = os.MkdirAll(dir, 0o700)
	}
	return os.WriteFile(path, data, 0o600)
}

// Describe renders the blocklist for operator display (sorted).
func (b *Blocklist) Describe() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	ips := make([]string, 0, len(b.ips))
	for ip := range b.ips {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	keys := make([]string, 0, len(b.pubkeys))
	for k := range b.pubkeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return fmt.Sprintf("ips: %v\npubkeys: %v", ips, keys)
}

// Blocklist is the operator (IP/pubkey) blocklist. It is safe for
// concurrent use. Comparison of pubkeys uses constant time so
// membership is not leaked via timing.
type Blocklist struct {
	mu      sync.RWMutex
	ips     map[string]bool
	pubkeys map[string]bool
	path    string
}

// NewBlocklist loads path ("" = DefaultDir()/blocklist.json);
// missing file starts empty.
func NewBlocklist(path string) (*Blocklist, error) {
	if path == "" {
		path = filepath.Join(DefaultDir(), "blocklist.json")
	}
	b := &Blocklist{ips: make(map[string]bool), pubkeys: make(map[string]bool), path: path}
	if data, err := os.ReadFile(path); err == nil {
		var saved struct {
			IPs     []string `json:"ips"`
			Pubkeys []string `json:"pubkeys"`
		}
		if err := json.Unmarshal(data, &saved); err != nil {
			return nil, fmt.Errorf("nodes: corrupt blocklist %s: %w", path, err)
		}
		for _, ip := range saved.IPs {
			b.ips[normalizeIP(ip)] = true
		}
		for _, k := range saved.Pubkeys {
			b.pubkeys[k] = true
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("nodes: read blocklist: %w", err)
	}
	return b, nil
}

// saveLocked persists to path with 0600 permissions.
func (b *Blocklist) saveLocked() error {
	saved := struct {
		IPs     []string `json:"ips"`
		Pubkeys []string `json:"pubkeys"`
	}{}
	for ip := range b.ips {
		saved.IPs = append(saved.IPs, ip)
	}
	for k := range b.pubkeys {
		saved.Pubkeys = append(saved.Pubkeys, k)
	}
	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(b.path); dir != "" {
		_ = os.MkdirAll(dir, 0o700)
	}
	return os.WriteFile(b.path, data, 0o600)
}

// BlockIP adds ip (persisted). Empty input is rejected.
func (b *Blocklist) BlockIP(ip string) error {
	if ip == "" {
		return errors.New("nodes: empty IP")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ips[normalizeIP(ip)] = true
	return b.saveLocked()
}

// UnblockIP removes ip (persisted).
func (b *Blocklist) UnblockIP(ip string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.ips, normalizeIP(ip))
	return b.saveLocked()
}

// BlockPubkey adds a client pubkey (persisted).
func (b *Blocklist) BlockPubkey(pubkey string) error {
	if pubkey == "" {
		return errors.New("nodes: empty pubkey")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pubkeys[pubkey] = true
	return b.saveLocked()
}

// UnblockPubkey removes a client pubkey (persisted).
func (b *Blocklist) UnblockPubkey(pubkey string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.pubkeys, pubkey)
	return b.saveLocked()
}

// IsBlockedIP reports IP membership.
func (b *Blocklist) IsBlockedIP(ip string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.ips[normalizeIP(ip)]
}

// IsBlockedPubkey reports pubkey membership using constant-time
// comparison over entries.
func (b *Blocklist) IsBlockedPubkey(pubkey string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for k := range b.pubkeys {
		if subtle.ConstantTimeCompare([]byte(k), []byte(pubkey)) == 1 {
			return true
		}
	}
	return false
}

// Complaint is one abuse report. Counters only for accounting scope:
// reporter, timestamp, reason, action. NEVER traffic content.
type Complaint struct {
	Reporter  string    `json:"reporter"`
	At        time.Time `json:"at"`
	Reason    string    `json:"reason"`
	Action    string    `json:"action"`
	SubjectIP string    `json:"subject_ip,omitempty"`
}

// ComplaintLog appends complaints to a JSONL file. Safe for
// concurrent use.
type ComplaintLog struct {
	mu   sync.Mutex
	path string
}

// NewComplaintLog opens path ("" = DefaultDir()/complaints.jsonl).
func NewComplaintLog(path string) *ComplaintLog {
	if path == "" {
		path = filepath.Join(DefaultDir(), "complaints.jsonl")
	}
	return &ComplaintLog{path: path}
}

// Report appends a complaint. Reporter and reason are required;
// subjectIP may be "" when the report is not IP-scoped.
func (l *ComplaintLog) Report(reporter, reason, action, subjectIP string) (Complaint, error) {
	if reporter == "" || reason == "" {
		return Complaint{}, errors.New("nodes: reporter and reason required")
	}
	c := Complaint{
		Reporter:  reporter,
		At:        time.Now().UTC(),
		Reason:    reason,
		Action:    action,
		SubjectIP: normalizeIP(subjectIP),
	}
	if subjectIP == "" {
		c.SubjectIP = ""
	}
	data, err := json.Marshal(c)
	if err != nil {
		return Complaint{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if dir := filepath.Dir(l.path); dir != "" {
		_ = os.MkdirAll(dir, 0o700)
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return Complaint{}, fmt.Errorf("nodes: open complaint log: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(data, '\n')); err != nil {
		return Complaint{}, fmt.Errorf("nodes: write complaint: %w", err)
	}
	return c, nil
}

// Count returns the number of logged complaints (for the auto-trigger).
func (l *ComplaintLog) Count() (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	data, err := os.ReadFile(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	n := 0
	for _, line := range splitLines(data) {
		if len(line) > 0 {
			n++
		}
	}
	return n, nil
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	out = append(out, b[start:])
	return out
}
// AbuseGuard bundles limiter + blocklist + complaints + policy for a
// Controller. The Controller owns one (see the hook fields); nil guard
// means enforcement off (open local dev default).
type AbuseGuard struct {
	mu         sync.Mutex
	limiter    *RateLimiter
	blocklist  *Blocklist
	complaints *ComplaintLog
	policy     AbusePolicy
	// onTrigger fires when the auto-trigger flips emergency disable;
	// wired by the controller to emit + persist the event.
	onTrigger func(count int)
}

// NewAbuseGuard builds a guard; nil limiter/blocklist/complaints are
// replaced with defaults (blocklist load failure is returned).
func NewAbuseGuard(policy AbusePolicy, limiter *RateLimiter, blocklist *Blocklist, complaints *ComplaintLog) (*AbuseGuard, error) {
	if limiter == nil {
		limiter = NewRateLimiter(DefaultRateLimitConfig(), nil)
	}
	if blocklist == nil {
		var err error
		blocklist, err = NewBlocklist("")
		if err != nil {
			return nil, err
		}
	}
	if complaints == nil {
		complaints = NewComplaintLog("")
	}
	return &AbuseGuard{
		limiter:    limiter,
		blocklist:  blocklist,
		complaints: complaints,
		policy:     policy.normalize(),
	}, nil
}

// PreAuthorize enforces blocklist then rate limit for an authorize
// attempt. clientIP is the peer address (may be ""), clientPubkey the
// presented key. Blocked/limited attempts return ErrBlocked /
// ErrRateLimited (both 429-class in the API).
func (g *AbuseGuard) PreAuthorize(clientIP, clientPubkey string) error {
	if g == nil {
		return nil
	}
	if g.blocklist.IsBlockedIP(clientIP) || g.blocklist.IsBlockedPubkey(clientPubkey) {
		return ErrBlocked
	}
	if !g.limiter.AllowAuthorize(clientIP) {
		return ErrRateLimited
	}
	return nil
}

// AllowMgmt enforces the management-API bucket.
func (g *AbuseGuard) AllowMgmt(clientIP string) bool {
	if g == nil {
		return true
	}
	return g.limiter.AllowMgmt(clientIP)
}

// ReportComplaint logs a complaint and evaluates the auto-trigger.
// When policy.AutoDisable is on and the count reaches the threshold,
// it calls onTrigger (the controller flips EmergencyDisable, persists
// the event, and logs loudly). Default policy: no trigger, just log.
func (g *AbuseGuard) ReportComplaint(reporter, reason, action, subjectIP string) (Complaint, error) {
	if g == nil {
		return Complaint{}, errors.New("nodes: no abuse guard configured")
	}
	c, err := g.complaints.Report(reporter, reason, action, subjectIP)
	if err != nil {
		return Complaint{}, err
	}
	g.mu.Lock()
	policy := g.policy
	fn := g.onTrigger
	g.mu.Unlock()
	if !policy.AutoDisable {
		return c, nil
	}
	n, err := g.complaints.Count()
	if err != nil {
		return c, nil // count failure must never trigger disable
	}
	if n >= policy.ComplaintThreshold && fn != nil {
		fn(n)
	}
	return c, nil
}

// SetPolicy replaces the abuse policy at runtime.
func (g *AbuseGuard) SetPolicy(p AbusePolicy) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.policy = p.normalize()
}

// abusePrecheck is the Controller.Authorize hook: blocklist then rate
// limit. Nil guard means enforcement off.
func (c *Controller) abusePrecheck(endpoint, clientPubkey string) error {
	g := c.abuse
	if g == nil {
		return nil
	}
	return g.PreAuthorize(endpoint, clientPubkey)
}

// SetAbuseGuard installs the enforcement guard and wires the
// auto-trigger: when the complaint threshold trips, EmergencyDisable
// flips on, an ABUSE_AUTODISABLE event fires, and the decision is
// logged loudly. The operator persists the change via config.
func (c *Controller) SetAbuseGuard(g *AbuseGuard) {
	c.mu.Lock()
	c.abuse = g
	c.mu.Unlock()
	if g == nil {
		return
	}
	g.mu.Lock()
	g.onTrigger = func(count int) {
		c.mu.Lock()
		c.cfg.EmergencyDisable = true
		c.mu.Unlock()
		c.emit("ABUSE_AUTODISABLE", map[string]any{"complaints": count})
		log.Printf("nodes: ABUSE auto-trigger: %d complaints, emergency disable ON (operator must persist config + review complaints.jsonl)", count)
	}
	g.mu.Unlock()
}

// AbuseGuard exposes the installed guard (may be nil).
func (c *Controller) AbuseGuard() *AbuseGuard {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.abuse
}

// AllowMgmtRequest enforces the management-API bucket for a peer IP.
// Nil guard allows (open local dev default).
func (c *Controller) AllowMgmtRequest(peerIP string) bool {
	c.mu.Lock()
	g := c.abuse
	c.mu.Unlock()
	if g == nil {
		return true
	}
	return g.AllowMgmt(peerIP)
}

// ReportAbuse logs a complaint (reporter/timestamp/reason/action only,
// never traffic content) and evaluates the auto-trigger.
func (c *Controller) ReportAbuse(reporter, reason, action, subjectIP string) (Complaint, error) {
	c.mu.Lock()
	g := c.abuse
	c.mu.Unlock()
	if g == nil {
		return Complaint{}, errors.New("nodes: no abuse guard configured (wire SetAbuseGuard first)")
	}
	return g.ReportComplaint(reporter, reason, action, subjectIP)
}
