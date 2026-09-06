// Audit regression tests (owned by HardenAgent).
//
// Each test proves one fixed finding from docs/AUDIT.md: it fails on
// the pre-fix behavior and passes after the fix. Only public APIs are
// used; no traffic content is fabricated anywhere.
package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dero-veilnet/veilnet/internal/nodes"
	"github.com/dero-veilnet/veilnet/internal/payments"
	"github.com/dero-veilnet/veilnet/internal/session"
	"github.com/dero-veilnet/veilnet/internal/tokens"
	"github.com/dero-veilnet/veilnet/internal/tunnel"
	"github.com/dero-veilnet/veilnet/internal/wireguard"
)

// ---------------------------------------------------------------------------
// Tokens: forgery / replay / expiry / revocation
// ---------------------------------------------------------------------------

func TestAuditTokenForgeryRejected(t *testing.T) {
	iss := tokens.NewIssuer()
	tok, err := iss.Mint("node1", "sess1", time.Hour, tokens.ScopeExit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.Validate(tok.Raw); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	// Wrong secret, same id.
	if _, err := iss.Validate(tok.ID + ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); !errors.Is(err, tokens.ErrInvalid) {
		t.Fatalf("forged secret: got %v, want ErrInvalid", err)
	}
	// Unknown id.
	if _, err := iss.Validate("ffffffffffffffffffffffffffffffff." + tok.Secret); !errors.Is(err, tokens.ErrInvalid) {
		t.Fatalf("unknown id: got %v, want ErrInvalid", err)
	}
	// Malformed.
	for _, bad := range []string{"", "nodelim", ".secret", "id."} {
		if _, err := iss.Validate(bad); !errors.Is(err, tokens.ErrInvalid) {
			t.Fatalf("malformed %q: got %v, want ErrInvalid", bad, err)
		}
	}
}

func TestAuditTokenReplayAfterRevokeSticks(t *testing.T) {
	iss := tokens.NewIssuer()
	tok, err := iss.Mint("node1", "sess1", time.Hour, tokens.ScopeExit)
	if err != nil {
		t.Fatal(err)
	}
	if err := iss.Revoke(tok.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := iss.Validate(tok.Raw); !errors.Is(err, tokens.ErrRevoked) {
			t.Fatalf("replay %d: got %v, want ErrRevoked", i, err)
		}
	}
}

func TestAuditTokenExpiryAndSweepGrace(t *testing.T) {
	iss := tokens.NewIssuer()
	tok, err := iss.Mint("node1", "sess1", 2*time.Millisecond, tokens.ScopeExit)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, err := iss.Validate(tok.Raw)
		if errors.Is(err, tokens.ErrExpired) {
			break
		}
		if err != nil {
			t.Fatalf("pre-expiry validate: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("token never expired")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Within the 24h grace, Sweep must NOT collect the record: replays
	// still report ErrExpired (not ErrInvalid-forged).
	if n := iss.Sweep(); n != 0 {
		t.Fatalf("sweep collected %d records inside grace, want 0", n)
	}
	if _, err := iss.Validate(tok.Raw); !errors.Is(err, tokens.ErrExpired) {
		t.Fatalf("post-sweep replay: got %v, want ErrExpired", err)
	}
}

// ---------------------------------------------------------------------------
// Session: revocation, expiry, dev-validator hardening
// ---------------------------------------------------------------------------

func testStaticManager(t *testing.T, m map[string]session.Token) *session.Manager {
	t.Helper()
	return session.NewManager(session.NewStaticValidator(m), session.Options{})
}

func TestAuditSessionRevocationBlocksReauthorize(t *testing.T) {
	mgr := testStaticManager(t, map[string]session.Token{
		"raw-token-1": {ID: "tid1", NodeID: "n1", SessionID: "s1", ExpiresAt: time.Now().Add(time.Hour), Scope: session.ScopeExit},
	})
	s, err := mgr.Authorize("raw-token-1", "pubkey1", "100.64.0.2", "1.2.3.4:51820")
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Revoke(s.TokenID); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Authorize("raw-token-1", "pubkey1", "100.64.0.2", "1.2.3.4:51820"); !errors.Is(err, session.ErrRevoked) {
		t.Fatalf("re-authorize after revoke: got %v, want ErrRevoked", err)
	}
}

func TestAuditSessionExpiredTokenRejected(t *testing.T) {
	mgr := testStaticManager(t, map[string]session.Token{
		"raw-old": {ID: "tid-old", NodeID: "n1", SessionID: "s1", ExpiresAt: time.Now().Add(-time.Minute), Scope: session.ScopeExit},
	})
	if _, err := mgr.Authorize("raw-old", "pubkey1", "100.64.0.2", "1.2.3.4:51820"); !errors.Is(err, session.ErrExpired) {
		t.Fatalf("expired token: got %v, want ErrExpired", err)
	}
}

func TestAuditDevValidatorExpirySuffixAndIDs(t *testing.T) {
	v := session.AllowAnyExpiryCheckedValidator{DefaultTTL: time.Hour}
	past := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	if _, err := v.Validate("payload|" + past); !errors.Is(err, session.ErrExpired) {
		t.Fatalf("past suffix: got %v, want ErrExpired", err)
	}
	if _, err := v.Validate("payload|not-a-time"); !errors.Is(err, session.ErrInvalid) {
		t.Fatalf("malformed suffix: got %v, want ErrInvalid", err)
	}
	a, err := v.Validate("token-alpha")
	if err != nil {
		t.Fatal(err)
	}
	b, err := v.Validate("token-alpha!")
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == b.ID {
		t.Fatal("distinct dev tokens share an ID (8-char truncation bug)")
	}
	if len(a.ID) != len("dev-")+64 {
		t.Fatalf("dev ID len = %d, want dev-+64 hex", len(a.ID))
	}
	// Suffix form preserves the payload as session id with caller expiry.
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	c, err := v.Validate("sess-9|" + future)
	if err != nil {
		t.Fatal(err)
	}
	if c.SessionID != "sess-9" {
		t.Fatalf("session id = %q, want sess-9", c.SessionID)
	}
}

// ---------------------------------------------------------------------------
// Payments: receipt tamper, overspend, settlement aggregation
// ---------------------------------------------------------------------------

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func signedReceipt(t *testing.T, priv ed25519.PrivateKey, id, sess, node string, amount int64) payments.Receipt {
	t.Helper()
	r := payments.Receipt{
		ID: id, SessionID: sess, NodeID: node, TokenID: "tok-" + sess,
		RxBytes: 1000, TxBytes: 500, Minutes: 10, Amount: amount,
	}
	if err := payments.SignReceipt(&r, priv); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAuditReceiptTamperRejected(t *testing.T) {
	svc := payments.NewService(payments.Options{Approver: payments.AutoApprover{}})
	priv := testKey(t)
	r := signedReceipt(t, priv, "rcpt-1", "sess-t", "node-t", 100)
	r.Amount = 999999 // tamper after signing
	if err := svc.RecordReceipt(r); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered receipt: got %v, want signature failure", err)
	}
	// Untouched receipt records fine.
	r2 := signedReceipt(t, priv, "rcpt-2", "sess-t", "node-t", 100)
	if err := svc.RecordReceipt(r2); err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}
	// Replay of the same receipt id is a duplicate.
	if err := svc.RecordReceipt(r2); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("replayed receipt: got %v, want duplicate error", err)
	}
	// Negative amounts never enter the store.
	r3 := payments.Receipt{ID: "rcpt-3", SessionID: "sess-t", NodeID: "node-t", Amount: -50}
	if err := payments.SignReceipt(&r3, priv); err != nil {
		t.Fatal(err)
	}
	if err := svc.RecordReceipt(r3); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("negative receipt: got %v, want negative-amount error", err)
	}
}

func TestAuditReceiptOverspendRejected(t *testing.T) {
	svc := payments.NewService(payments.Options{Approver: payments.AutoApprover{}})
	ctx := context.Background()
	// 2.0 DERO funded (deposit recorded even without a wallet).
	if _, err := svc.Authorize(ctx, "node-o", "dero-operator-addr", "sess-o", 2.0); err != nil {
		t.Fatalf("fund: %v", err)
	}
	priv := testKey(t)
	// 2.0 DERO = 200000 atomic; this receipt exceeds the deposit.
	big := signedReceipt(t, priv, "rcpt-big", "sess-o", "node-o", 200001)
	if err := svc.RecordReceipt(big); err == nil || !strings.Contains(err.Error(), "exceeds remaining") {
		t.Fatalf("overspend receipt: got %v, want exceeds-remaining error", err)
	}
	// A receipt within credit records fine.
	ok := signedReceipt(t, priv, "rcpt-ok", "sess-o", "node-o", 1000)
	if err := svc.RecordReceipt(ok); err != nil {
		t.Fatalf("in-credit receipt rejected: %v", err)
	}
}

func TestAuditSettlementCheckedAggregation(t *testing.T) {
	newSvc := func() *payments.Service {
		return payments.NewService(payments.Options{Approver: payments.AutoApprover{}})
	}
	priv := testKey(t)
	ctx := context.Background()

	// Empty batch aborts.
	if _, err := newSvc().RecordSettlement(ctx, "node-x"); err == nil {
		t.Fatal("empty settlement must fail")
	}
	// int64 overflow aborts instead of wrapping (unknown sessions skip
	// the prepaid overspend guard, isolating aggregation).
	svc := newSvc()
	huge := int64(math.MaxInt64)/2 + 100
	if err := svc.RecordReceipt(signedReceipt(t, priv, "h1", "sess-h1", "node-h", huge)); err != nil {
		t.Fatal(err)
	}
	if err := svc.RecordReceipt(signedReceipt(t, priv, "h2", "sess-h2", "node-h", huge)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RecordSettlement(ctx, "node-h"); err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("overflowing settlement: got %v, want overflow error", err)
	}
	// Deterministic batch IDs: the same receipt set settles under the
	// same ID on independent services (idempotent retry support).
	svcA, svcB := newSvc(), newSvc()
	for _, svc := range []*payments.Service{svcA, svcB} {
		if err := svc.RecordReceipt(signedReceipt(t, priv, "d1", "sess-d", "node-d", 300)); err != nil {
			t.Fatal(err)
		}
		if err := svc.RecordReceipt(signedReceipt(t, priv, "d2", "sess-d", "node-d", 400)); err != nil {
			t.Fatal(err)
		}
	}
	stA, err := svcA.RecordSettlement(ctx, "node-d")
	if err != nil {
		t.Fatal(err)
	}
	stB, err := svcB.RecordSettlement(ctx, "node-d")
	if err != nil {
		t.Fatal(err)
	}
	if stA.Total != 700 {
		t.Fatalf("settlement total = %d, want 700", stA.Total)
	}
	if stA.ID != stB.ID || !strings.HasPrefix(stA.ID, "stl-") {
		t.Fatalf("batch ids differ or malformed: %q vs %q", stA.ID, stB.ID)
	}
}

// ---------------------------------------------------------------------------
// Nodes: rate limit, blocklist persistence, complaint auto-trigger
// ---------------------------------------------------------------------------

func testPubkey(t *testing.T) string {
	t.Helper()
	_, pub, err := wireguard.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func testController(t *testing.T, v session.TokenValidator) *nodes.Controller {
	t.Helper()
	cfg := nodes.DefaultConfig()
	ctrl, err := nodes.NewController(cfg, v, nodes.NewFakeWGManager("audit0"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return ctrl
}

func tmpGuard(t *testing.T, policy nodes.AbusePolicy, cfg nodes.RateLimitConfig) *nodes.AbuseGuard {
	t.Helper()
	dir := t.TempDir()
	bl, err := nodes.NewBlocklist(filepath.Join(dir, "blocklist.json"))
	if err != nil {
		t.Fatal(err)
	}
	g, err := nodes.NewAbuseGuard(policy,
		nodes.NewRateLimiter(cfg, nil),
		bl,
		nodes.NewComplaintLog(filepath.Join(dir, "complaints.jsonl")))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestAuditAuthorizeRateLimit(t *testing.T) {
	ctrl := testController(t, session.AllowAnyExpiryCheckedValidator{})
	ctrl.SetAbuseGuard(tmpGuard(t, nodes.AbusePolicy{}, nodes.RateLimitConfig{
		AuthorizeBurst: 2, AuthorizeWindow: time.Minute,
	}))
	ep := "9.9.9.9:51820"
	for i := 0; i < 2; i++ {
		if _, err := ctrl.Authorize(fmt.Sprintf("flood-%d", i), testPubkey(t), ep); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := ctrl.Authorize("flood-2", testPubkey(t), ep); !errors.Is(err, nodes.ErrRateLimited) {
		t.Fatalf("flood attempt: got %v, want ErrRateLimited", err)
	}
}

func TestAuditAuthorizeFloodIs429Class(t *testing.T) {
	ctrl := testController(t, session.AllowAnyExpiryCheckedValidator{})
	ctrl.SetAbuseGuard(tmpGuard(t, nodes.AbusePolicy{}, nodes.RateLimitConfig{
		AuthorizeBurst: 3, AuthorizeWindow: time.Minute,
	}))
	srv := nodes.NewServer(ctrl, "audit-bearer")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go srv.ServeListener(ln) //nolint:errcheck
	time.Sleep(100 * time.Millisecond)

	post := func(i int) int {
		body := fmt.Sprintf(`{"token":"http-%d","client_pubkey":%q,"endpoint":"9.9.9.9:51820"}`,
			i, testPubkey(t))
		req, _ := http.NewRequest("POST", "http://"+ln.Addr().String()+"/session/authorize", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer audit-bearer")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	for i := 0; i < 3; i++ {
		if code := post(i); code != http.StatusOK {
			t.Fatalf("attempt %d: status %d, want 200", i, code)
		}
	}
	if code := post(99); code != http.StatusTooManyRequests {
		t.Fatalf("flood attempt: status %d, want 429", code)
	}
}

func TestAuditBlocklistPersistsAndEnforces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.json")
	bl, err := nodes.NewBlocklist(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := bl.BlockIP("203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	pub := testPubkey(t)
	if err := bl.BlockPubkey(pub); err != nil {
		t.Fatal(err)
	}
	// Reload from disk: entries survive restarts.
	bl2, err := nodes.NewBlocklist(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bl2.IsBlockedIP("203.0.113.7") {
		t.Fatal("reloaded blocklist lost IP entry")
	}
	if !bl2.IsBlockedPubkey(pub) {
		t.Fatal("reloaded blocklist lost pubkey entry")
	}
	// Enforcement at the controller: the reloaded blocklist (as a
	// restarted daemon would load it) blocks the pubkey.
	ctrl := testController(t, session.AllowAnyExpiryCheckedValidator{})
	dir2 := t.TempDir()
	g, err := nodes.NewAbuseGuard(nodes.AbusePolicy{},
		nodes.NewRateLimiter(nodes.DefaultRateLimitConfig(), nil),
		bl2,
		nodes.NewComplaintLog(filepath.Join(dir2, "complaints.jsonl")))
	if err != nil {
		t.Fatal(err)
	}
	ctrl.SetAbuseGuard(g)
	if _, err := ctrl.Authorize("blk-1", pub, "198.51.100.2:51820"); !errors.Is(err, nodes.ErrBlocked) {
		t.Fatalf("blocked pubkey authorized: %v", err)
	}
}

func TestAuditComplaintAutoTrigger(t *testing.T) {
	ctrl := testController(t, session.AllowAnyExpiryCheckedValidator{})
	ctrl.SetAbuseGuard(tmpGuard(t,
		nodes.AbusePolicy{AutoDisable: true, ComplaintThreshold: 2},
		nodes.DefaultRateLimitConfig()))
	if _, err := ctrl.ReportAbuse("op@example.com", "spam", "logged", ""); err != nil {
		t.Fatal(err)
	}
	if ctrl.Config().EmergencyDisable {
		t.Fatal("trigger fired after 1 complaint with threshold 2")
	}
	if _, err := ctrl.ReportAbuse("op@example.com", "portscan", "blocked", "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	if !ctrl.Config().EmergencyDisable {
		t.Fatal("auto-trigger did not flip EmergencyDisable at threshold")
	}
	if _, err := ctrl.Authorize("after-disable", testPubkey(t), "198.51.100.3:51820"); !errors.Is(err, nodes.ErrDisabled) {
		t.Fatalf("post-trigger authorize: got %v, want ErrDisabled", err)
	}
}

func TestAuditComplaintLogPrivacy(t *testing.T) {
	dir := t.TempDir()
	clog := nodes.NewComplaintLog(filepath.Join(dir, "complaints.jsonl"))
	c, err := clog.Report("reporter@example.com", "dmca", "blocked", "203.0.113.11")
	if err != nil {
		t.Fatal(err)
	}
	if c.Reporter == "" || c.Reason == "" || c.Action == "" || c.At.IsZero() {
		t.Fatalf("complaint missing required fields: %+v", c)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "complaints.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{"payload", "dns", "url", "rx_bytes", "tx_bytes", "content"} {
		if strings.Contains(lower, `"`+forbidden+`"`) {
			t.Fatalf("complaint log contains traffic-content key %q: %s", forbidden, raw)
		}
	}
	var decoded nodes.Complaint
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &decoded); err != nil {
		t.Fatalf("complaint line is not JSON: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tunnel: backend selection is logged and named in Status().Detail
// ---------------------------------------------------------------------------

func TestAuditTunnelBackendDetail(t *testing.T) {
	privA, _, err := wireguard.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, pubB, err := wireguard.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	eng := tunnel.New(tunnel.WithInterfaceName("veilnet-audit-probe"))
	cfg := tunnel.WireGuardConfig{
		PrivateKey: privA,
		Addresses:  []string{"10.99.0.1/32"},
		Peers:      []tunnel.Peer{{PublicKey: pubB, Endpoint: "127.0.0.1:59999", AllowedIPs: []string{"10.99.0.2/32"}}},
	}
	if err := eng.Start(cfg); err != nil {
		// No privileges / no driver here: the engine must report DOWN
		// with an EMPTY Detail — never a faked backend name.
		st := eng.Status()
		if st.Detail != "" {
			t.Fatalf("failed Start reports Detail %q, want empty (no fake backends)", st.Detail)
		}
		t.Skipf("no data-plane privileges in this environment (%v); Detail-empty-on-failure verified", err)
	}
	defer eng.Stop()
	detail := eng.Status().Detail
	if detail == "" {
		t.Fatal("started engine reports empty Detail, want named backend")
	}
	if !strings.Contains(detail, "kernel") && !strings.Contains(detail, "userspace") {
		t.Fatalf("Detail %q names no known backend", detail)
	}
}
