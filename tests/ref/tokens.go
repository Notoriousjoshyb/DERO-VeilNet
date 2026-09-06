package ref

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// Token mirrors the Contract token fields.
type Token struct {
	ID        string
	NodeID    string
	SessionID string
	ExpiresAt time.Time
	Scope     string
	secret    string
}

// Manager issues 256-bit crypto/rand base64url tokens, verifies them in
// constant time, and enforces single-use revocation.
type Manager struct {
	mu      sync.Mutex
	secrets map[string]Token // id -> token
	revoked map[string]bool  // consumed or explicitly revoked ids
	now     func() time.Time
}

// NewManager returns an empty token manager.
func NewManager() *Manager {
	return &Manager{
		secrets: make(map[string]Token),
		revoked: make(map[string]bool),
		now:     time.Now,
	}
}

// SetClock overrides time for expiry testing.
func (m *Manager) SetClock(fn func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = fn
}

func newSecret() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
// Issue creates a token with the given TTL and returns the public Token
// descriptor plus its bearer authenticator ("id.secret"). The bearer is
// shown exactly once at issue time — the manager never reveals it again —
// mirroring how a client receives credentials out-of-band, never on-chain.
func (m *Manager) Issue(nodeID, sessionID, scope string, ttl time.Duration) (Token, string, error) {
	id, err := newSecret()
	if err != nil {
		return Token{}, "", err
	}
	secret, err := newSecret()
	if err != nil {
		return Token{}, "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t := Token{
		ID:        id,
		NodeID:    nodeID,
		SessionID: sessionID,
		ExpiresAt: m.now().Add(ttl),
		Scope:     scope,
		secret:    secret,
	}
	m.secrets[id] = t
	return t, id + "." + secret, nil
}

// SplitBearer separates a presented "id.secret" authenticator.
func SplitBearer(bearer string) (id, secret string, err error) {
	for i := range bearer {
		if bearer[i] == '.' {
			return bearer[:i], bearer[i+1:], nil
		}
	}
	return "", "", errors.New("ref: malformed bearer")
}

// VerifyBearer verifies a presented bearer string in one call.
func (m *Manager) VerifyBearer(bearer string) (Token, error) {
	id, secret, err := SplitBearer(bearer)
	if err != nil {
		return Token{}, err
	}
	return m.Verify(id, secret)
}

// ConsumeBearer consumes a presented bearer string in one call.
func (m *Manager) ConsumeBearer(bearer string) (Token, error) {
	id, secret, err := SplitBearer(bearer)
	if err != nil {
		return Token{}, err
	}
	return m.Consume(id, secret)
}

// Verify checks id+secret in constant time, then enforces expiry and
// single-use revocation. ok=false with a reason error on any failure.
func (m *Manager) Verify(id, secret string) (Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, known := m.secrets[id]
	// Always run a constant-time compare even for unknown ids so that
	// unknown vs wrong-secret are indistinguishable by timing.
	candidate := t.secret
	if !known {
		candidate = ""
	}
	if subtle.ConstantTimeCompare([]byte(candidate), []byte(secret)) != 1 || !known {
		return Token{}, errors.New("ref: token forged or unknown")
	}
	if m.revoked[id] {
		return Token{}, errors.New("ref: token already consumed")
	}
	if !m.now().Before(t.ExpiresAt) {
		return Token{}, errors.New("ref: token expired")
	}
	return t, nil
}

// Consume verifies and marks single-use: a second Verify fails.
func (m *Manager) Consume(id, secret string) (Token, error) {
	t, err := m.Verify(id, secret)
	if err != nil {
		return Token{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked[id] = true
	return t, nil
}

// Revoke marks an id unusable regardless of secret knowledge.
func (m *Manager) Revoke(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked[id] = true
}
