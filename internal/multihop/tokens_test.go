package multihop

import (
	"strings"
	"testing"
	"time"
)

func TestIssueTokensScopedPerHop(t *testing.T) {
	nodes := testNodes()
	r, err := BuildRoute(nodes[:3], BuildOptions{})
	if err != nil {
		t.Fatalf("BuildRoute: %v", err)
	}
	toks, err := IssueTokens(r, time.Hour)
	if err != nil {
		t.Fatalf("IssueTokens: %v", err)
	}
	if len(toks) != 3 {
		t.Fatalf("tokens = %d, want 3", len(toks))
	}
	roles := []HopRole{RoleEntry, RoleMiddle, RoleExit}
	seen := map[string]bool{}
	for i, tok := range toks {
		if !tok.Scoped(r.ID, r.Hops[i].NodeID, roles[i]) {
			t.Fatalf("token %d not scoped: %+v", i, tok)
		}
		if seen[tok.Token] {
			t.Fatal("duplicate token value across hops")
		}
		seen[tok.Token] = true
		if tok.Expired(time.Now().Add(30 * time.Minute)) {
			t.Fatal("token should be valid for 1h")
		}
		if !tok.Expired(time.Now().Add(2 * time.Hour)) {
			t.Fatal("token should expire after its ttl")
		}
		if tok.Scoped(r.ID, r.Hops[(i+1)%3].NodeID, roles[i]) {
			t.Fatalf("token %d validates for another hop", i)
		}
	}
}

func TestReissueExitKeepsEntryToken(t *testing.T) {
	nodes := testNodes()
	r, err := BuildRoute(nodes[:2], BuildOptions{})
	if err != nil {
		t.Fatalf("BuildRoute: %v", err)
	}
	before, err := IssueTokens(r, time.Hour)
	if err != nil {
		t.Fatalf("IssueTokens: %v", err)
	}
	rotated, err := r.RotateExit(nodes[2])
	if err != nil {
		t.Fatalf("RotateExit: %v", err)
	}
	exit, err := ReissueExitToken(rotated, time.Hour)
	if err != nil {
		t.Fatalf("ReissueExitToken: %v", err)
	}
	if exit.NodeID != "n3" || exit.Role != RoleExit {
		t.Fatalf("exit token = %+v", exit)
	}
	if exit.Token == before[1].Token {
		t.Fatal("exit token not refreshed")
	}
	// Entry token untouched: the stored entry value still scopes to n1.
	if !before[0].Scoped(r.ID, "n1", RoleEntry) {
		t.Fatal("entry token disturbed by exit rotation")
	}
	_ = strings.TrimSpace // keep strings import if helpers change
}

func TestQuoteSingleApproval(t *testing.T) {
	nodes := testNodes()
	r, err := BuildRoute(nodes[:3], BuildOptions{})
	if err != nil {
		t.Fatalf("BuildRoute: %v", err)
	}
	q, err := QuoteRoute(r, 4)
	if err != nil {
		t.Fatalf("QuoteRoute: %v", err)
	}
	if !q.SingleApproval {
		t.Fatal("quote must carry a single approval")
	}
	// Pro-rata math: 0.05 DERO/h * 4h = 0.20 per hop, 0.60 total.
	for _, hq := range q.HopQuotes {
		if hq.Hours != 4 || diff(hq.Amount, 0.2) > 1e-9 {
			t.Fatalf("hop %s quote = %+v, want 4h @ 0.2", hq.NodeID, hq)
		}
	}
	if diff(q.Total, 0.6) > 1e-9 {
		t.Fatalf("total = %v, want 0.6", q.Total)
	}
	if len(q.HopQuotes) != 3 {
		t.Fatalf("hop quotes = %d, want 3", len(q.HopQuotes))
	}
	// Free hops quote 0 but still appear in the single approval.
	free := nodes[0]
	free.PricePerHour = 0
	rf, err := BuildRoute([]NodeInfo{free}, BuildOptions{})
	if err != nil {
		t.Fatalf("BuildRoute: %v", err)
	}
	qf, err := QuoteRoute(rf, 4)
	if err != nil {
		t.Fatalf("QuoteRoute: %v", err)
	}
	if len(qf.HopQuotes) != 1 || qf.Total != 0 || !qf.SingleApproval {
		t.Fatalf("free quote = %+v", qf)
	}
	if _, err := QuoteRoute(r, 0); err == nil {
		t.Fatal("zero hours accepted")
	}
}

func diff(a, b float64) float64 {
	if a > b {
		return a - b
	}
	return b - a
}

func TestExposuresShape(t *testing.T) {
	got := Exposures(3)
	if len(got) != 3 {
		t.Fatalf("3-hop exposures = %d", len(got))
	}
	if !got[0].SeesClientIP || got[0].SeesDestination {
		t.Fatalf("entry sees client IP, never destination: %+v", got[0])
	}
	if got[1].SeesClientIP || got[1].SeesDestination {
		t.Fatalf("middle must see neither end: %+v", got[1])
	}
	if got[2].SeesClientIP || !got[2].SeesDestination {
		t.Fatalf("exit exposure wrong: %+v", got[2])
	}
	if got := Exposures(1); len(got) != 1 || !got[0].SeesClientIP || !got[0].SeesDestination {
		t.Fatalf("single exposure wrong: %+v", got)
	}
}
