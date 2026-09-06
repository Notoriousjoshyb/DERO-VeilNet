package reputation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func signReceiptView(t *testing.T, r *receiptView, priv ed25519.PrivateKey) {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	r.NodePub = []byte(pub)
	r.Sig = ed25519.Sign(priv, receiptBody(*r))
}

func TestDoubleSettlementVerifies(t *testing.T) {
	_, nodePriv, _ := ed25519.GenerateKey(rand.Reader)
	mk := func(min uint64, amt int64) receiptView {
		r := receiptView{ID: "rc1", SessionID: "s", NodeID: "n1", TokenID: "tok", Minutes: min, Amount: amt}
		signReceiptView(t, &r, nodePriv)
		return r
	}
	proof, _ := json.Marshal(DoubleSettlementProof{A: mk(10, 100), B: mk(11, 200)})
	e := Evidence{Kind: KindDoubleSettlement, NodeID: "n1", Proof: proof, At: time.Now()}
	if err := e.Sign(testKey(t)); err != nil {
		t.Fatal(err)
	}
	if err := e.Verify(); err != nil {
		t.Fatalf("valid double-settlement rejected: %v", err)
	}
}

func TestDoubleSettlementIdenticalRejected(t *testing.T) {
	_, nodePriv, _ := ed25519.GenerateKey(rand.Reader)
	r := receiptView{ID: "rc1", SessionID: "s", NodeID: "n1"}
	signReceiptView(t, &r, nodePriv)
	proof, _ := json.Marshal(DoubleSettlementProof{A: r, B: r})
	e := Evidence{Kind: KindDoubleSettlement, NodeID: "n1", Proof: proof, At: time.Now()}
	_ = e.Sign(testKey(t))
	if err := e.Verify(); err == nil {
		t.Fatal("identical receipts must not prove double-settlement")
	}
}

func TestForgedReceiptVerifies(t *testing.T) {
	_, nodePriv, _ := ed25519.GenerateKey(rand.Reader)
	r := receiptView{ID: "rc9", SessionID: "s", NodeID: "n1", Amount: 5}
	signReceiptView(t, &r, nodePriv)
	r.Amount = 999 // tamper after signing
	proof, _ := json.Marshal(ForgedReceiptProof{Receipt: r})
	e := Evidence{Kind: KindForgedReceipt, NodeID: "n1", Proof: proof, At: time.Now()}
	if err := e.Sign(testKey(t)); err != nil {
		t.Fatal(err)
	}
	if err := e.Verify(); err != nil {
		t.Fatalf("valid forged-receipt proof rejected: %v", err)
	}
}

func TestForgedProofWithValidSigRejected(t *testing.T) {
	_, nodePriv, _ := ed25519.GenerateKey(rand.Reader)
	r := receiptView{ID: "rc9", SessionID: "s", NodeID: "n1"}
	signReceiptView(t, &r, nodePriv) // untouched: signature VALID
	proof, _ := json.Marshal(ForgedReceiptProof{Receipt: r})
	e := Evidence{Kind: KindForgedReceipt, NodeID: "n1", Proof: proof, At: time.Now()}
	_ = e.Sign(testKey(t))
	if err := e.Verify(); err == nil {
		t.Fatal("valid signature must not prove forgery")
	}
}

func TestTamperedEvidenceRejected(t *testing.T) {
	e := Evidence{Kind: KindUptime, NodeID: "n1", Proof: []byte(`{"uptime":1}`), At: time.Now()}
	if err := e.Sign(testKey(t)); err != nil {
		t.Fatal(err)
	}
	e.NodeID = "n2" // tamper after signing
	if err := e.Verify(); err == nil {
		t.Fatal("tampered evidence must fail verification")
	}
}

func TestAdvisoryRoundTrip(t *testing.T) {
	a := Advisory{NodeID: "n1", Uptime: 0.9, AvgLatencyMs: 42, Samples: 7}
	if err := a.Sign(testKey(t)); err != nil {
		t.Fatal(err)
	}
	raw, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAdvisory(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.NodeID != "n1" || got.Samples != 7 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	raw[len(raw)-5] ^= 0xff // tamper
	if _, err := ParseAdvisory(raw); err == nil {
		t.Fatal("tampered advisory must fail verification")
	}
}

func TestScoreSlashZeroes(t *testing.T) {
	if got := Score(ScoreInput{BondDERO: 100, Uptime: 1, History: 1}); got != 1 {
		t.Fatalf("perfect score = %v, want 1", got)
	}
	if got := Score(ScoreInput{BondDERO: 100, Uptime: 1, History: 1, Slashed: true}); got != 0 {
		t.Fatalf("slashed score = %v, want 0", got)
	}
}

func TestStoreSlashAndScore(t *testing.T) {
	_, nodePriv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	mk := func(min uint64) receiptView {
		r := receiptView{ID: "rc", SessionID: "s", NodeID: "n1", Minutes: min}
		signReceiptView(t, &r, nodePriv)
		return r
	}
	proof, _ := json.Marshal(DoubleSettlementProof{A: mk(1), B: mk(2)})
	e := Evidence{Kind: KindDoubleSettlement, NodeID: "n1", Proof: proof, At: time.Now()}
	_ = e.Sign(testKey(t))
	if err := s.Add(e); err != nil {
		t.Fatal(err)
	}
	if !s.Slashed("n1") {
		t.Fatal("expected slashed")
	}
	if got := s.ReputationScore("n1"); got != 0 {
		t.Fatalf("slashed score = %v, want 0", got)
	}
	if err := s.Add(Evidence{Kind: "bogus", NodeID: "n1"}); err == nil {
		t.Fatal("bad evidence must be rejected")
	}
}
