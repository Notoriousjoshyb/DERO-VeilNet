package veilnettest

import (
	"strings"
	"testing"
	"time"

	"github.com/dero-veilnet/veilnet/tests/ref"
)

func TestTokenCarries256BitEntropy(t *testing.T) {
	m := ref.NewManager()
	tok, bearer, err := m.Issue("nodeA", "sess1", "connect", time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// 32 bytes -> base64url RawURLEncoding = 43 chars, no padding, URL-safe.
	if len(tok.ID) != 43 {
		t.Fatalf("token id len = %d, want 43 (256 bits base64url)", len(tok.ID))
	}
	for _, c := range tok.ID {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			t.Fatalf("token id char %q not base64url", c)
		}
	}
	if !strings.HasPrefix(bearer, tok.ID+".") {
		t.Fatal("bearer must present as id.secret")
	}
	secret := strings.TrimPrefix(bearer, tok.ID+".")
	if len(secret) != 43 {
		t.Fatalf("bearer secret len = %d, want 43 (256 bits)", len(secret))
	}
	if tok.NodeID != "nodeA" || tok.SessionID != "sess1" || tok.Scope != "connect" {
		t.Fatalf("fields = %+v", tok)
	}
	if tok.ExpiresAt.Sub(time.Now()) > time.Hour || time.Now().After(tok.ExpiresAt) {
		t.Fatal("token TTL not honored")
	}
}

func TestTokenIDsAreUnique(t *testing.T) {
	m := ref.NewManager()
	seen := map[string]bool{}
	for range 200 {
		tok, _, err := m.Issue("n", "s", "connect", time.Hour)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if seen[tok.ID] {
			t.Fatal("duplicate token id")
		}
		seen[tok.ID] = true
	}
}

func TestTokenVerifyAcceptsGenuineBearer(t *testing.T) {
	m := ref.NewManager()
	_, bearer, err := m.Issue("nodeA", "sess1", "connect", time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := m.VerifyBearer(bearer)
	if err != nil {
		t.Fatalf("genuine bearer rejected: %v", err)
	}
	if got.SessionID != "sess1" {
		t.Fatalf("verified session = %q", got.SessionID)
	}
}

func TestTokenForgedBearerRejected(t *testing.T) {
	m := ref.NewManager()
	tok, bearer, err := m.Issue("nodeA", "sess1", "connect", time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	id, _, _ := ref.SplitBearer(bearer)
	for _, forged := range []string{
		"not-a-bearer",
		id + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"",
	} {
		if _, err := m.VerifyBearer(forged); err == nil {
			t.Fatalf("forged bearer %q accepted", forged)
		}
	}
	_ = tok
}

func TestTokenSingleUseConsume(t *testing.T) {
	m := ref.NewManager()
	_, bearer, err := m.Issue("nodeA", "sess1", "connect", time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := m.ConsumeBearer(bearer); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := m.VerifyBearer(bearer); err == nil {
		t.Fatal("consumed token reused: must be rejected")
	}
	if _, err := m.ConsumeBearer(bearer); err == nil {
		t.Fatal("double consume must be rejected")
	}
}

func TestTokenExpiryEnforced(t *testing.T) {
	m := ref.NewManager()
	now := time.Now()
	m.SetClock(func() time.Time { return now })
	_, bearer, err := m.Issue("nodeA", "sess1", "connect", 5*time.Minute)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := m.VerifyBearer(bearer); err != nil {
		t.Fatalf("fresh token rejected: %v", err)
	}
	now = now.Add(10 * time.Minute)
	if _, err := m.VerifyBearer(bearer); err == nil {
		t.Fatal("expired token must be rejected")
	}
}

func TestTokenRevokeBlocksUse(t *testing.T) {
	m := ref.NewManager()
	tok, bearer, err := m.Issue("nodeA", "sess1", "connect", time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	m.Revoke(tok.ID)
	if _, err := m.VerifyBearer(bearer); err == nil {
		t.Fatal("revoked token must be rejected")
	}
}
