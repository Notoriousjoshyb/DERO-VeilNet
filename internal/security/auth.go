// Package security provides small, auditable guards for the management
// surface: token auth, metadata sanitizing, command-injection rejection,
// management ACL + rate limits, log redaction, and the privacy diagnostics
// engine. All helpers are stdlib-only and side-effect free so they can be
// unit-tested and reused by the service, GUI backend, and node operator
// stack without importing them.
package security

import (
	"crypto/subtle"
	"errors"
	"time"
)

// Token mirrors the contract token fields {id, node_id, session_id,
// expires_at, scope}: 256-bit crypto/rand base64url at issuance (issuance
// lives with the session owner), constant-time comparison here.
type Token struct {
	ID        string
	NodeID    string
	SessionID string
	ExpiresAt time.Time
	Scope     string
}

// CheckToken validates a presented token against the expected value:
// constant-time secret comparison, expiry enforcement, and scope match.
// Returns a descriptive error; callers must not distinguish failure modes
// to unauthenticated clients beyond "denied".
func CheckToken(presented, expected Token, presentedSecret, expectedSecret string) error {
	if presented.ID == "" || expected.ID == "" {
		return errors.New("security: empty token id")
	}
	if subtle.ConstantTimeCompare([]byte(presentedSecret), []byte(expectedSecret)) != 1 {
		return errors.New("security: token denied")
	}
	if subtle.ConstantTimeCompare([]byte(presented.ID), []byte(expected.ID)) != 1 {
		return errors.New("security: token denied")
	}
	if time.Now().UTC().After(expected.ExpiresAt) {
		return errors.New("security: token expired")
	}
	if presented.Scope != expected.Scope {
		return errors.New("security: token scope mismatch")
	}
	return nil
}

// CheckScope authorizes a token for one required scope. Scopes are exact
// strings (e.g. "session:use", "mgmt:read", "mgmt:write"); no wildcards.
func CheckScope(tok Token, want string) error {
	if tok.Scope != want {
		return errors.New("security: scope denied")
	}
	if time.Now().UTC().After(tok.ExpiresAt) {
		return errors.New("security: token expired")
	}
	return nil
}
