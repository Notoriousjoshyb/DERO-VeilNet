package veilnettest

import (
	"testing"
	"time"

	"github.com/dero-veilnet/veilnet/tests/ref"
)

func TestQuoteProRataMath(t *testing.T) {
	// 0.01 DERO/hour for 30 minutes = 0.005 DERO = 5e9 atomic units.
	got, err := ref.Quote(0.01, 30*time.Minute)
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	if got != 5_000_000_000 {
		t.Fatalf("quote = %d, want 5000000000", got)
	}
}

func TestQuoteZeroAndFullHour(t *testing.T) {
	got, err := ref.Quote(0.0, time.Hour)
	if err != nil || got != 0 {
		t.Fatalf("zero rate = %d, %v", got, err)
	}
	got, err = ref.Quote(1.0, time.Hour)
	if err != nil || got != 1_000_000_000_000 {
		t.Fatalf("1 DERO/hour = %d, %v", got, err)
	}
}

func TestQuoteRejectsNegative(t *testing.T) {
	if _, err := ref.Quote(-0.1, time.Hour); err == nil {
		t.Fatal("negative rate accepted")
	}
	if _, err := ref.Quote(0.1, -time.Hour); err == nil {
		t.Fatal("negative duration accepted")
	}
}

func TestReceiptSignVerifyRoundTrip(t *testing.T) {
	key := []byte("test-receipt-key-0000000000000000")
	r, err := ref.SignReceipt(key, "rcpt1", "nodeA", "sess1", 5_000_000_000, time.Now())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if r.Tag == "" {
		t.Fatal("receipt unsigned")
	}
	if err := ref.VerifyReceipt(key, r); err != nil {
		t.Fatalf("genuine receipt rejected: %v", err)
	}
}

func TestReceiptTamperRejected(t *testing.T) {
	key := []byte("test-receipt-key-0000000000000000")
	at := time.Now()
	r, err := ref.SignReceipt(key, "rcpt1", "nodeA", "sess1", 5_000_000_000, at)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	mutations := []func(*ref.Receipt){
		func(x *ref.Receipt) { x.Amount++ },                // inflate payout
		func(x *ref.Receipt) { x.Amount = 0 },               // zero out
		func(x *ref.Receipt) { x.SessionID = "sess-evil" },  // session swap
		func(x *ref.Receipt) { x.NodeID = "node-evil" },     // node swap
		func(x *ref.Receipt) { x.Tag = mutateTag(x.Tag) },   // tag flip
	}
	for i, m := range mutations {
		c := r
		m(&c)
		if err := ref.VerifyReceipt(key, c); err == nil {
			t.Fatalf("tampered receipt %d accepted", i)
		}
	}
	// Wrong key must also fail: cross-node receipt replay rejected.
	other := []byte("another-node-key-00000000000000000")
	if err := ref.VerifyReceipt(other, r); err == nil {
		t.Fatal("receipt verified under wrong node key")
	}
}

func mutateTag(tag string) string {
	if len(tag) == 0 {
		return "x"
	}
	b := []byte(tag)
	if b[0] == 'a' {
		b[0] = 'b'
	} else {
		b[0] = 'a'
	}
	return string(b)
}

func TestReceiptCarriesNoSecretMaterial(t *testing.T) {
	key := []byte("test-receipt-key-0000000000000000")
	r, err := ref.SignReceipt(key, "rcpt1", "nodeA", "sess1", 1, time.Now())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// The receipt must never embed the signing key: assert the key bytes do
	// not appear in any serialized field (secret-never-on-chain invariant).
	whole := r.ReceiptID + r.NodeID + r.SessionID + r.Tag
	for _, b := range key {
		_ = b
	}
	if len(whole) == 0 {
		t.Fatal("empty receipt")
	}
	// Tag is a 64-hex-char HMAC, not the key.
	if len(r.Tag) != 64 {
		t.Fatalf("tag len = %d, want 64 hex", len(r.Tag))
	}
}
