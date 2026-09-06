// Package tokens issues single-use prepaid session tokens.
//
// Token format: "<id>.<secret>" where id is 128-bit crypto/rand hex and
// secret is 256-bit crypto/rand base64url. Secrets are compared in
// constant time and consumed tokens enter a single-use revocation map.
// Expired tokens are rejected. Forged tokens (unknown id or wrong
// secret) are rejected.
//
// The node validates presented tokens through session.TokenValidator;
// see session.go for the adapter. No wallet material ever appears here:
// tokens are bearer credentials for data-plane access only, funded by
// prepaid DERO credit tracked in internal/payments.
package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
)

// Scopes bound into a token. They mirror internal/session ScopeExit /
// ScopeRelay so the adapter needs no translation table.
type Scope string

const (
	ScopeExit  Scope = "exit"
	ScopeRelay Scope = "relay"
)

// DefaultTTL bounds Mint when the caller passes ttl <= 0.
const DefaultTTL = 4 * time.Hour

var (
	ErrInvalid = errors.New("tokens: invalid token")
	ErrExpired = errors.New("tokens: token expired")
	ErrRevoked = errors.New("tokens: token revoked")
	ErrUnknown = errors.New("tokens: unknown token")
)

// Token is one minted bearer credential.
type Token struct {
	ID        string
	NodeID    string
	SessionID string
	ExpiresAt time.Time
	Scope     Scope
	// Secret is populated only on Mint. Validate never returns it.
	Secret string
	// Raw is the full "<id>.<secret>" bearer string.
	Raw string
}

type record struct {
	nodeID    string
	sessionID string
	expiresAt time.Time
	scope     Scope
	secret    string
}

// Issuer mints and validates tokens. It is safe for concurrent use.
type Issuer struct {
	mu      sync.Mutex
	tokens  map[string]*record
	revoked map[string]bool
	now     func() time.Time
}

// NewIssuer returns an empty Issuer.
func NewIssuer() *Issuer {
	return &Issuer{
		tokens:  make(map[string]*record),
		revoked: make(map[string]bool),
		now:     time.Now,
	}
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randSecret() (string, error) {
	b := make([]byte, 32) // 256-bit
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Mint creates a token for nodeID/sessionID valid for ttl.
// ttl <= 0 falls back to DefaultTTL. scope "" falls back to ScopeExit.
func (in *Issuer) Mint(nodeID, sessionID string, ttl time.Duration, scope Scope) (Token, error) {
	if strings.TrimSpace(nodeID) == "" || strings.TrimSpace(sessionID) == "" {
		return Token{}, ErrInvalid
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	if scope == "" {
		scope = ScopeExit
	}
	if scope != ScopeExit && scope != ScopeRelay {
		return Token{}, ErrInvalid
	}
	id, err := randHex(16) // 128-bit
	if err != nil {
		return Token{}, err
	}
	secret, err := randSecret()
	if err != nil {
		return Token{}, err
	}
	exp := in.now().Add(ttl)
	in.mu.Lock()
	in.tokens[id] = &record{
		nodeID:    nodeID,
		sessionID: sessionID,
		expiresAt: exp,
		scope:     scope,
		secret:    secret,
	}
	in.mu.Unlock()
	return Token{
		ID:        id,
		NodeID:    nodeID,
		SessionID: sessionID,
		ExpiresAt: exp,
		Scope:     scope,
		Secret:    secret,
		Raw:       id + "." + secret,
	}, nil
}

// Validate checks a presented "<id>.<secret>" string. Success returns
// the token fields (without the secret). Unknown ids and wrong secrets
// both return ErrInvalid (indistinguishable: id validity is not
// leaked); revoked and expired ids return ErrRevoked and ErrExpired.
// Secret comparison hashes both sides with SHA-256 before
// ConstantTimeCompare so secrets of any length compare in constant
// time (raw ConstantTimeCompare short-circuits on length mismatch).
// Unknown ids run a dummy comparison so the timing profile matches the
// wrong-secret path.
func (in *Issuer) Validate(raw string) (Token, error) {
	id, secret, ok := strings.Cut(raw, ".")
	if !ok || id == "" || secret == "" {
		return Token{}, ErrInvalid
	}
	in.mu.Lock()
	rec, known := in.tokens[id]
	revoked := in.revoked[id]
	now := in.now()
	in.mu.Unlock()
	presented := sha256.Sum256([]byte(secret))
	if !known {
		var dummy [32]byte
		subtle.ConstantTimeCompare(presented[:], dummy[:])
		return Token{}, ErrInvalid
	}
	if revoked {
		return Token{}, ErrRevoked
	}
	expected := sha256.Sum256([]byte(rec.secret))
	if subtle.ConstantTimeCompare(presented[:], expected[:]) != 1 {
		return Token{}, ErrInvalid
	}
	if !now.Before(rec.expiresAt) {
		return Token{}, ErrExpired
	}
	return Token{
		ID:        id,
		NodeID:    rec.nodeID,
		SessionID: rec.sessionID,
		ExpiresAt: rec.expiresAt,
		Scope:     rec.scope,
		Raw:       raw,
	}, nil
}

// Revoke single-use consumes a token id. Re-validate after revoke
// returns ErrRevoked. Unknown ids return ErrUnknown.
func (in *Issuer) Revoke(id string) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if _, ok := in.tokens[id]; !ok {
		return ErrUnknown
	}
	in.revoked[id] = true
	return nil
}

// IsRevoked reports revocation. Comparison over stored ids uses
// constant time so membership is not leaked via timing.
func (in *Issuer) IsRevoked(id string) bool {
	in.mu.Lock()
	defer in.mu.Unlock()
	var found int
	for k := range in.revoked {
		if subtle.ConstantTimeCompare([]byte(k), []byte(id)) == 1 {
			found = 1
		}
	}
	return found == 1
}

// expiredGrace keeps expired records after expiry so replays in the
// window still report ErrExpired (not ErrInvalid) and cannot be
// confused with forged ids. Only records expired longer than the
// grace are collected. Revocation entries are kept forever: a revoked
// id must stay revoked past its expiry.
const expiredGrace = 24 * time.Hour

// Sweep removes long-expired, unrevoked records to bound memory.
func (in *Issuer) Sweep() int {
	in.mu.Lock()
	defer in.mu.Unlock()
	n := 0
	now := in.now()
	for id, rec := range in.tokens {
		if now.Sub(rec.expiresAt) > expiredGrace && !in.revoked[id] {
			delete(in.tokens, id)
			n++
		}
	}
	return n
}
