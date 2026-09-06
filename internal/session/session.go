// Package session manages node-side authorized VPN sessions.
//
// A session binds a payment token to a WireGuard peer: per-token byte
// counters, time quota / expiry, and a background sweeper that evicts
// expired sessions. Token signature verification itself is injected via
// the TokenValidator interface so this package never imports the
// payments tree (no import cycles); the node wires the real validator
// at startup and tests inject fakes.
package session

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
)

// Token scopes.
const (
	ScopeExit  = "exit"
	ScopeRelay = "relay"
)

// Token mirrors the contract token fields relevant to the node.
type Token struct {
	ID        string
	NodeID    string
	SessionID string
	ExpiresAt time.Time
	Scope     string
	Raw       string
}

// TokenValidator verifies a presented token string.
// Implementations MUST use constant-time comparison for secrets.
type TokenValidator interface {
	Validate(tokenString string) (Token, error)
}

// ValidatorFunc adapts a function to TokenValidator.
type ValidatorFunc func(string) (Token, error)

// Validate implements TokenValidator.
func (f ValidatorFunc) Validate(s string) (Token, error) { return f(s) }

var (
	// ErrInvalid is returned for malformed or unknown tokens.
	ErrInvalid = errors.New("session: invalid token")
	// ErrExpired is returned when the token is past its expiry.
	ErrExpired = errors.New("session: token expired")
	// ErrRevoked is returned for revoked / single-use-consumed tokens.
	ErrRevoked = errors.New("session: token revoked")
	// ErrUnknown is returned for unknown session/token IDs.
	ErrUnknown = errors.New("session: unknown session")
)

// DenyValidator rejects every token. It is the safe default: the node
// refuses to authorize peers until the operator wires the real
// payments validator.
type DenyValidator struct{ Reason string }

// Validate implements TokenValidator.
func (d DenyValidator) Validate(string) (Token, error) {
	if d.Reason != "" {
		return Token{}, errors.New("session: " + d.Reason)
	}
	return Token{}, errors.New("session: no token validator configured")
}

// StaticValidator accepts tokens from a fixed map (tests / local dev).
// Comparison of the presented secret uses constant time.
type StaticValidator struct {
	mu     sync.RWMutex
	tokens map[string]Token
}

// NewStaticValidator builds a validator from a token map.
func NewStaticValidator(tokens map[string]Token) *StaticValidator {
	cp := make(map[string]Token, len(tokens))
	for k, v := range tokens {
		cp[k] = v
	}
	return &StaticValidator{tokens: cp}
}

// Validate implements TokenValidator. The map is scanned in full with
// constant-time comparison per entry and no early return, so neither
// membership nor position leaks via timing.
func (s *StaticValidator) Validate(raw string) (Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var match *Token
	matched := 0
	for k, tok := range s.tokens {
		if subtle.ConstantTimeCompare([]byte(k), []byte(raw)) == 1 {
			c := tok
			match = &c
			matched = 1
		}
	}
	if matched != 1 || match == nil {
		return Token{}, ErrInvalid
	}
	match.Raw = raw
	if !match.ExpiresAt.IsZero() && time.Now().After(match.ExpiresAt) {
		return Token{}, ErrExpired
	}
	return *match, nil
}

// AllowAnyExpiryCheckedValidator accepts any non-empty token whose
// expiry (if encoded as RFC3339 suffix "payload|expiry") is in the
// future. DEV ONLY: the node enables it solely under an explicit
// --dev flag, never by default.
type AllowAnyExpiryCheckedValidator struct{ DefaultTTL time.Duration }

// Validate implements TokenValidator. IDs are SHA-256 over the full
// presented string (no 8-char truncation: distinct tokens must never
// share an ID). A "payload|RFC3339-expiry" suffix is honored: past
// expiries reject with ErrExpired, malformed suffixes with ErrInvalid.
func (a AllowAnyExpiryCheckedValidator) Validate(raw string) (Token, error) {
	if raw == "" {
		return Token{}, ErrInvalid
	}
	payload := raw
	if i := strings.LastIndex(raw, "|"); i >= 0 {
		exp, perr := time.Parse(time.RFC3339, raw[i+1:])
		if perr != nil {
			return Token{}, ErrInvalid
		}
		if !time.Now().Before(exp) {
			return Token{}, ErrExpired
		}
		payload = raw[:i]
		if payload == "" {
			return Token{}, ErrInvalid
		}
		return Token{
			ID:        devID(raw),
			SessionID: payload,
			ExpiresAt: exp,
			Scope:     ScopeExit,
			Raw:       raw,
		}, nil
	}
	ttl := a.DefaultTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	return Token{
		ID:        devID(raw),
		SessionID: payload,
		ExpiresAt: time.Now().Add(ttl),
		Scope:     ScopeExit,
		Raw:       raw,
	}, nil
}

// devID derives a collision-resistant session ID from the full token.
func devID(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return "dev-" + hex.EncodeToString(sum[:])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Session is one authorized client slot.
type Session struct {
	TokenID      string
	NodeID       string
	SessionID    string
	ClientPubkey string
	AssignedIP   string
	Endpoint     string
	Scope        string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Revoked      bool

	mu           sync.Mutex
	RxBytes      uint64
	TxBytes      uint64
	LastActivity time.Time
}

// Expired reports whether the session is past its quota.
func (s *Session) Expired(now time.Time) bool {
	if s.Revoked {
		return true
	}
	if s.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(s.ExpiresAt)
}

// Snapshot is a frozen, mutex-free copy of a Session safe to pass by value,
// emit over the event bus, and return from Active/SweepOnce.
type Snapshot struct {
	TokenID      string
	NodeID       string
	SessionID    string
	ClientPubkey string
	AssignedIP   string
	Endpoint     string
	Scope        string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Revoked      bool
	RxBytes      uint64
	TxBytes      uint64
	LastActivity time.Time
}

// Expired reports whether the snapshot is past its quota.
func (s Snapshot) Expired(now time.Time) bool {
	if s.Revoked {
		return true
	}
	if s.ExpiresAt.IsZero() {
		return false
	}
	return !now.Before(s.ExpiresAt)
}

// Snapshot returns a copy safe for external use.
func (s *Session) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Snapshot{
		TokenID:      s.TokenID,
		NodeID:       s.NodeID,
		SessionID:    s.SessionID,
		ClientPubkey: s.ClientPubkey,
		AssignedIP:   s.AssignedIP,
		Endpoint:     s.Endpoint,
		Scope:        s.Scope,
		CreatedAt:    s.CreatedAt,
		ExpiresAt:    s.ExpiresAt,
		Revoked:      s.Revoked,
		RxBytes:      s.RxBytes,
		TxBytes:      s.TxBytes,
		LastActivity: s.LastActivity,
	}
}

// Options tunes the Manager.
type Options struct {
	// MaxSessionDuration caps every session lifetime. Zero = no extra cap.
	MaxSessionDuration time.Duration
	// OnExpire fires (best-effort, non-blocking) for each swept session.
	OnExpire func(Snapshot)
	// OnEvent publishes lifecycle events; nil = no-op.
	OnEvent func(event string, v any)
}

// Manager tracks live sessions, byte counters, and revocations.
type Manager struct {
	validator TokenValidator
	opts      Options

	mu      sync.Mutex
	byToken map[string]*Session
	byIP    map[string]*Session
	// revoked is the single-use revocation map: consumed or explicitly
	// revoked token IDs. Entries never leave during process lifetime.
	revoked map[string]time.Time

	authorizedTotal uint64
	expiredTotal    uint64
}

// NewManager creates a session manager. A nil validator becomes DenyValidator.
func NewManager(v TokenValidator, opts Options) *Manager {
	if v == nil {
		v = DenyValidator{}
	}
	return &Manager{
		validator: v,
		opts:      opts,
		byToken:   make(map[string]*Session),
		byIP:      make(map[string]*Session),
		revoked:   make(map[string]time.Time),
	}
}

func (m *Manager) emit(event string, v any) {
	if m.opts.OnEvent != nil {
		m.opts.OnEvent(event, v)
	}
}

// Authorize validates the token and opens a session for clientPubkey.
// assignedIP and endpoint are recorded for accounting / firewall use.
func (m *Manager) Authorize(tokenString, clientPubkey, assignedIP, endpoint string) (*Session, error) {
	tok, err := m.validator.Validate(tokenString)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if !tok.ExpiresAt.IsZero() && !now.Before(tok.ExpiresAt) {
		return nil, ErrExpired
	}
	expires := tok.ExpiresAt
	if m.opts.MaxSessionDuration > 0 {
		if cap := now.Add(m.opts.MaxSessionDuration); expires.IsZero() || cap.Before(expires) {
			expires = cap
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// Constant-time scan (no early return): revocation membership must
	// not leak via lookup timing. Matches IsRevoked semantics.
	revoked := 0
	for id := range m.revoked {
		if subtle.ConstantTimeCompare([]byte(id), []byte(tok.ID)) == 1 {
			revoked = 1
		}
	}
	if revoked == 1 {
		return nil, ErrRevoked
	}
	if existing, ok := m.byToken[tok.ID]; ok && !existing.Snapshot().Expired(now) {
		return nil, errors.New("session: token already active")
	}
	s := &Session{
		TokenID:      tok.ID,
		NodeID:       tok.NodeID,
		SessionID:    tok.SessionID,
		ClientPubkey: clientPubkey,
		AssignedIP:   assignedIP,
		Endpoint:     endpoint,
		Scope:        tok.Scope,
		CreatedAt:    now,
		ExpiresAt:    expires,
		LastActivity: now,
	}
	m.byToken[tok.ID] = s
	if assignedIP != "" {
		m.byIP[assignedIP] = s
	}
	m.authorizedTotal++
	m.emit("SESSION_AUTHORIZED", s.Snapshot())
	return s, nil
}

// Revoke consumes a token: the session is marked revoked, the token ID
// enters the single-use revocation map, and re-authorize is rejected.
func (m *Manager) Revoke(tokenID string) error {
	m.mu.Lock()
	s, ok := m.byToken[tokenID]
	if !ok {
		m.mu.Unlock()
		return ErrUnknown
	}
	delete(m.byToken, tokenID)
	if s.AssignedIP != "" {
		if cur, ok := m.byIP[s.AssignedIP]; ok && cur == s {
			delete(m.byIP, s.AssignedIP)
		}
	}
	m.revoked[tokenID] = time.Now()
	m.mu.Unlock()

	s.mu.Lock()
	s.Revoked = true
	s.mu.Unlock()
	snap := s.Snapshot()
	m.emit("SESSION_EXPIRED", snap)
	return nil
}

// IsRevoked reports revocation using constant-time comparison over IDs
// with no early return.
func (m *Manager) IsRevoked(tokenID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	found := 0
	for id := range m.revoked {
		if subtle.ConstantTimeCompare([]byte(id), []byte(tokenID)) == 1 {
			found = 1
		}
	}
	return found == 1
}

// Get returns the live session for a token ID.
func (m *Manager) Get(tokenID string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byToken[tokenID]
	if !ok {
		return nil, ErrUnknown
	}
	return s, nil
}

// AddBytes attributes traffic to a token for accounting/quota display.
// It never inspects traffic content — only counters.
func (m *Manager) AddBytes(tokenID string, rx, tx uint64) error {
	m.mu.Lock()
	s, ok := m.byToken[tokenID]
	m.mu.Unlock()
	if !ok {
		return ErrUnknown
	}
	s.mu.Lock()
	s.RxBytes += rx
	s.TxBytes += tx
	s.LastActivity = time.Now()
	s.mu.Unlock()
	return nil
}

// Active returns snapshots of non-expired, non-revoked sessions.
func (m *Manager) Active() []Snapshot {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Snapshot, 0, len(m.byToken))
	for _, s := range m.byToken {
		snap := s.Snapshot()
		if snap.Expired(now) {
			continue
		}
		out = append(out, snap)
	}
	return out
}

// ActiveCount returns the live session count.
func (m *Manager) ActiveCount() int { return len(m.Active()) }

// Totals returns lifetime counters.
func (m *Manager) Totals() (authorized, expired uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.authorizedTotal, m.expiredTotal
}

// SweepOnce evicts expired sessions, returning their snapshots.
// The controller uses these to remove WireGuard peers.
func (m *Manager) SweepOnce(now time.Time) []Snapshot {
	m.mu.Lock()
	var done []*Session
	for id, s := range m.byToken {
		if s.Snapshot().Expired(now) {
			done = append(done, s)
			delete(m.byToken, id)
			if s.AssignedIP != "" {
				if cur, ok := m.byIP[s.AssignedIP]; ok && cur == s {
					delete(m.byIP, s.AssignedIP)
				}
			}
			m.revoked[id] = now
			m.expiredTotal++
		}
	}
	m.mu.Unlock()

	out := make([]Snapshot, 0, len(done))
	for _, s := range done {
		snap := s.Snapshot()
		out = append(out, snap)
		m.emit("SESSION_EXPIRED", snap)
		if m.opts.OnExpire != nil {
			m.opts.OnExpire(snap)
		}
	}
	return out
}
