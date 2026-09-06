// Session adapter: lets the node validate bearer tokens without
// importing the payments tree.
//
// internal/session deliberately defines its own Token struct and
// TokenValidator interface so it never imports payments. This file is
// the single bridge: it maps tokens.Token onto session.Token and maps
// issuer errors onto the session sentinel errors the node sweeps on.
package tokens

import (
	"errors"

	"github.com/dero-veilnet/veilnet/internal/session"
)

// SessionValidator wraps an Issuer as a session.TokenValidator.
type SessionValidator struct {
	Issuer *Issuer
}

// NewSessionValidator returns a validator backed by iss. A nil issuer
// becomes a deny-all validator (safe default: refuse peers).
func NewSessionValidator(iss *Issuer) SessionValidator {
	return SessionValidator{Issuer: iss}
}

// Validate implements session.TokenValidator with constant-time secret
// comparison inherited from Issuer.Validate.
func (v SessionValidator) Validate(raw string) (session.Token, error) {
	if v.Issuer == nil {
		return session.Token{}, session.ErrInvalid
	}
	tok, err := v.Issuer.Validate(raw)
	if err != nil {
		switch {
		case errors.Is(err, ErrExpired):
			return session.Token{}, session.ErrExpired
		case errors.Is(err, ErrRevoked):
			return session.Token{}, session.ErrRevoked
		default:
			return session.Token{}, session.ErrInvalid
		}
	}
	return session.Token{
		ID:        tok.ID,
		NodeID:    tok.NodeID,
		SessionID: tok.SessionID,
		ExpiresAt: tok.ExpiresAt,
		Scope:     string(tok.Scope),
		Raw:       tok.Raw,
	}, nil
}
