package reputation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Evidence kinds. The SLASHABLE set carries offline-verifiable proof;
// the ADVISORY set carries local observations only.
const (
	// KindDoubleSettlement is SLASHABLE: two distinct receipts sharing
	// one receipt ID, both validly signed by the same node key.
	KindDoubleSettlement = "double-settlement"
	// KindForgedReceipt is SLASHABLE: a receipt presented as settled
	// whose node signature does NOT verify (offline check).
	KindForgedReceipt = "forged-receipt"
	// KindLatency, KindUptime, KindDowntime are ADVISORY summaries.
	KindLatency  = "latency"
	KindUptime   = "uptime"
	KindDowntime = "downtime"
)

// IsSlashable reports whether kind carries slash proof.
func IsSlashable(kind string) bool {
	return kind == KindDoubleSettlement || kind == KindForgedReceipt
}

// IsAdvisory reports whether kind is a gossip-eligible observation.
func IsAdvisory(kind string) bool {
	return kind == KindLatency || kind == KindUptime || kind == KindDowntime
}

// Evidence is one reputation datum about a node.
type Evidence struct {
	Kind     string `json:"kind"`
	NodeID   string `json:"node_id"`
	Proof    []byte `json:"proof"`    // kind-specific JSON (see below)
	Reporter []byte `json:"reporter"` // 32-byte ed25519 reporter pubkey
	Sig      []byte `json:"sig"`      // reporter signature over body
	At       time.Time `json:"at"`
}

// bodyBytes is the canonical signed body: kind|node_id|proof|unix-seconds.
func (e Evidence) bodyBytes() []byte {
	var buf bytes.Buffer
	buf.WriteString(e.Kind)
	buf.WriteByte('|')
	buf.WriteString(e.NodeID)
	buf.WriteByte('|')
	buf.Write(e.Proof)
	buf.WriteByte('|')
	fmt.Fprintf(&buf, "%d", e.At.Unix())
	return buf.Bytes()
}

// Sign fills Reporter/At/Sig with the reporter's key. At is truncated to
// seconds so the body round-trips byte-identically.
func (e *Evidence) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("reputation: bad reporter private key size")
	}
	pub := priv.Public().(ed25519.PublicKey)
	e.Reporter = []byte(pub)
	e.At = e.At.UTC().Truncate(time.Second)
	if e.At.IsZero() {
		e.At = time.Now().UTC().Truncate(time.Second)
	}
	e.Sig = ed25519.Sign(priv, e.bodyBytes())
	return nil
}

// verifyReporter checks the reporter signature only.
func (e Evidence) verifyReporter() error {
	if len(e.Reporter) != ed25519.PublicKeySize {
		return errors.New("reputation: bad reporter key size")
	}
	if len(e.Sig) != ed25519.SignatureSize {
		return errors.New("reputation: bad evidence signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(e.Reporter), e.bodyBytes(), e.Sig) {
		return errors.New("reputation: evidence signature verification failed")
	}
	return nil
}

// receiptView is the minimal receipt shape both slash proofs use, so the
// proof verifies offline without importing the payments package
// (importing it would also work; this keeps reputation dependency-free).
type receiptView struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	NodeID    string `json:"node_id"`
	TokenID   string `json:"token_id"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	Minutes   uint64 `json:"minutes"`
	Amount    int64  `json:"amount_atomic"`
	NodePub   []byte `json:"node_pub"`
	Sig       []byte `json:"sig"`
}

func receiptBody(r receiptView) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%s|%d|%d|%d|%d",
		r.ID, r.SessionID, r.NodeID, r.TokenID,
		r.RxBytes, r.TxBytes, r.Minutes, r.Amount))
}

func verifyReceiptView(r receiptView) error {
	if len(r.NodePub) != ed25519.PublicKeySize {
		return errors.New("reputation: bad node public key size")
	}
	if len(r.Sig) != ed25519.SignatureSize {
		return errors.New("reputation: bad receipt signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(r.NodePub), receiptBody(r), r.Sig) {
		return errors.New("reputation: receipt signature verification failed")
	}
	return nil
}

// DoubleSettlementProof proves one node key signed two different receipt
// bodies under one receipt ID (settled twice / double-signed).
type DoubleSettlementProof struct {
	A receiptView `json:"a"`
	B receiptView `json:"b"`
}

// verifyDoubleSettlement checks: same ID, different bodies, both
// signatures valid, both from the same node key.
func verifyDoubleSettlement(raw []byte) error {
	var p DoubleSettlementProof
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("reputation: bad double-settlement proof: %w", err)
	}
	if p.A.ID == "" || p.A.ID != p.B.ID {
		return errors.New("reputation: double-settlement needs matching non-empty receipt ids")
	}
	if bytes.Equal(receiptBody(p.A), receiptBody(p.B)) {
		return errors.New("reputation: double-settlement needs distinct receipt bodies")
	}
	if err := verifyReceiptView(p.A); err != nil {
		return fmt.Errorf("reputation: double-settlement receipt A invalid: %w", err)
	}
	if err := verifyReceiptView(p.B); err != nil {
		return fmt.Errorf("reputation: double-settlement receipt B invalid: %w", err)
	}
	if !bytes.Equal(p.A.NodePub, p.B.NodePub) {
		return errors.New("reputation: double-settlement receipts from different node keys")
	}
	return nil
}

// ForgedReceiptProof is a receipt presented as node-settled whose node
// signature does NOT verify. The offline check confirms invalidity, i.e.
// the evidence demonstrates the forgery it alleges.
type ForgedReceiptProof struct {
	Receipt receiptView `json:"receipt"`
	Note    string      `json:"note,omitempty"`
}

// verifyForgedReceipt checks the receipt signature FAILS (that failure is
// the proof) while the receipt itself is well-formed.
func verifyForgedReceipt(raw []byte) error {
	var p ForgedReceiptProof
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return fmt.Errorf("reputation: bad forged-receipt proof: %w", err)
	}
	if p.Receipt.ID == "" {
		return errors.New("reputation: forged-receipt needs a receipt id")
	}
	if len(p.Receipt.NodePub) != ed25519.PublicKeySize {
		return errors.New("reputation: forged-receipt needs a 32-byte node key")
	}
	if len(p.Receipt.Sig) != ed25519.SignatureSize {
		return errors.New("reputation: forged-receipt needs a 64-byte signature")
	}
	if verifyReceiptView(p.Receipt) == nil {
		return errors.New("reputation: forged-receipt proof carries a VALID signature, nothing forged")
	}
	return nil
}

// Verify checks reporter authenticity plus kind-specific proof validity.
// Slashable proofs verify fully offline (ed25519 only). Advisory kinds
// require only a valid reporter signature and well-formed JSON proof.
func (e Evidence) Verify() error {
	switch e.Kind {
	case KindDoubleSettlement, KindForgedReceipt, KindLatency, KindUptime, KindDowntime:
	default:
		return fmt.Errorf("reputation: unknown evidence kind %q", e.Kind)
	}
	if e.NodeID == "" {
		return errors.New("reputation: empty node_id")
	}
	if err := e.verifyReporter(); err != nil {
		return err
	}
	switch e.Kind {
	case KindDoubleSettlement:
		return verifyDoubleSettlement(e.Proof)
	case KindForgedReceipt:
		return verifyForgedReceipt(e.Proof)
	default:
		var v map[string]any
		if err := json.Unmarshal(e.Proof, &v); err != nil {
			return fmt.Errorf("reputation: bad advisory proof: %w", err)
		}
		return nil
	}
}
