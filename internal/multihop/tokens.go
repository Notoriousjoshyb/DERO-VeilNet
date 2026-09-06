// Per-hop layered session tokens and single-approval multi-hop quoting.
//
// Each circuit hop carries its own session token scoped to (route, node,
// role): the entry token authorises the client at the entry, the middle
// token chains entry->middle, the exit token chains to the exit. Tokens
// are bearer placeholders minted client-side here; the real payment
// backing (DERO funding + explicit user approval) lives in
// internal/payments. Rotating the exit re-issues only the exit token: the
// entry token — the client's identity at the guard — is never re-exposed
// to a new entry.
//
// Billing is pro-rata per hop: Quote{HopQuotes, Total, SingleApproval}
// prices hours*hop-rate per hop and presents ONE approval dialog covering
// the whole circuit (SingleApproval is always true). No per-packet
// transactions, no silent per-hop prompts.
package multihop

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// HopRole scopes a session token to one circuit position.
type HopRole string

const (
	RoleEntry  HopRole = "entry"
	RoleMiddle HopRole = "middle"
	RoleExit   HopRole = "exit"
	RoleSingle HopRole = "single"
)

// hopRoles maps path position to scope: single-hop routes use one
// "single" token; longer routes use entry/[middle]/exit.
func hopRoles(n int) []HopRole {
	switch n {
	case 1:
		return []HopRole{RoleSingle}
	case 2:
		return []HopRole{RoleEntry, RoleExit}
	default:
		roles := make([]HopRole, n)
		roles[0] = RoleEntry
		for i := 1; i < n-1; i++ {
			roles[i] = RoleMiddle
		}
		roles[n-1] = RoleExit
		return roles
	}
}

// SessionToken is one hop-scoped bearer token. Token is a random 128-bit
// hex value (no custom crypto: randomness only, authentication stays with
// the WireGuard + payment layers). RouteID binds the token to its route;
// rotation re-issues downstream tokens under the same RouteID lineage.
type SessionToken struct {
	Token     string    `json:"token"`
	RouteID   string    `json:"route_id"`
	NodeID    string    `json:"node_id"`
	Role      HopRole   `json:"role"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Scoped reports whether t authorises nodeID at role on routeID.
func (t SessionToken) Scoped(routeID, nodeID string, role HopRole) bool {
	return t.RouteID == routeID && t.NodeID == nodeID && t.Role == role && t.Token != ""
}

// Expired reports whether t is past ExpiresAt at now.
func (t SessionToken) Expired(now time.Time) bool {
	return !now.Before(t.ExpiresAt)
}

func mintToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("multihop: token randomness unavailable")
	}
	return hex.EncodeToString(b[:]), nil
}

// IssueTokens mints one scoped token per route hop. ttl <= 0 means 24h.
// Tokens are independent values: compromising the exit token exposes
// neither the entry token nor any other hop.
func IssueTokens(r *Route, ttl time.Duration) ([]SessionToken, error) {
	if r == nil || len(r.Hops) == 0 {
		return nil, errors.New("multihop: cannot issue tokens without a route")
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	roles := hopRoles(len(r.Hops))
	now := time.Now().UTC()
	out := make([]SessionToken, len(r.Hops))
	for i, h := range r.Hops {
		v, err := mintToken()
		if err != nil {
			return nil, err
		}
		out[i] = SessionToken{
			Token:     v,
			RouteID:   r.ID,
			NodeID:    h.NodeID,
			Role:      roles[i],
			IssuedAt:  now,
			ExpiresAt: now.Add(ttl),
		}
	}
	return out, nil
}

// ReissueExitToken mints a fresh exit-scoped token after an exit rotation
// without touching the entry (or middle) tokens: pass the rotated route
// (same ID lineage, new exit) and receive the replacement exit token.
// The caller swaps it into the stored set; stored entry tokens are never
// re-issued, so the client is never re-exposed to a new entry.
func ReissueExitToken(r *Route, ttl time.Duration) (SessionToken, error) {
	if r == nil || len(r.Hops) == 0 {
		return SessionToken{}, errors.New("multihop: cannot re-issue exit token without a route")
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	v, err := mintToken()
	if err != nil {
		return SessionToken{}, err
	}
	role := RoleExit
	if len(r.Hops) == 1 {
		role = RoleSingle
	}
	now := time.Now().UTC()
	return SessionToken{
		Token:     v,
		RouteID:   r.ID,
		NodeID:    r.Exit().NodeID,
		Role:      role,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}, nil
}

// HopQuote prices one hop: Amount = PricePerHour * Hours (pro-rata).
type HopQuote struct {
	NodeID       string  `json:"node_id"`
	Role         HopRole `json:"role"`
	PricePerHour float64 `json:"price_per_hour_dero"`
	Hours        float64 `json:"hours"`
	Amount       float64 `json:"amount_dero"`
}

// Quote is the single-approval billing summary for a whole circuit:
// per-hop pro-rata shares plus the total the user approves once.
// SingleApproval is always true: the UI presents exactly one dialog for
// the circuit, never one prompt per hop.
type Quote struct {
	HopQuotes      []HopQuote `json:"hop_quotes"`
	Total          float64    `json:"total_dero"`
	SingleApproval bool       `json:"single_approval"`
}

// QuoteRoute prices hours of session time across every route hop.
// hours must be > 0; free hops (price 0) quote 0 but still appear so the
// user sees the full path they approve.
func QuoteRoute(r *Route, hours float64) (Quote, error) {
	if r == nil || len(r.Hops) == 0 {
		return Quote{}, errors.New("multihop: cannot quote an empty route")
	}
	if hours <= 0 {
		return Quote{}, fmt.Errorf("multihop: quote hours must be > 0, got %v", hours)
	}
	roles := hopRoles(len(r.Hops))
	q := Quote{HopQuotes: make([]HopQuote, len(r.Hops)), SingleApproval: true}
	for i, h := range r.Hops {
		amt := h.PricePerHour * hours
		q.HopQuotes[i] = HopQuote{
			NodeID:       h.NodeID,
			Role:         roles[i],
			PricePerHour: h.PricePerHour,
			Hours:        hours,
			Amount:       amt,
		}
		q.Total += amt
	}
	return q, nil
}
