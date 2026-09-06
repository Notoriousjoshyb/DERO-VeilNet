package reputation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Advisory is a signed ADVISORY gossip summary exchanged between clients.
// It carries observations only (uptime, latency, sample count) — never
// slash verdicts, never a global-kill. Recipients apply their own
// weights; a low advisory score only nudges local selection.
type Advisory struct {
	NodeID      string    `json:"node_id"`
	Uptime      float64   `json:"uptime"`        // 0..1
	AvgLatencyMs float64  `json:"avg_latency_ms"` // measured RTT, 0 = unknown
	Samples     int       `json:"samples"`
	Reporter    []byte    `json:"reporter"` // 32-byte ed25519 reporter pubkey
	Sig         []byte    `json:"sig"`      // reporter signature over body
	At          time.Time `json:"at"`
}

func (a Advisory) bodyBytes() []byte {
	var buf bytes.Buffer
	buf.WriteString(a.NodeID)
	buf.WriteByte('|')
	fmt.Fprintf(&buf, "%.6f|%.3f|%d|%d", a.Uptime, a.AvgLatencyMs, a.Samples, a.At.Unix())
	return buf.Bytes()
}

// Sign fills Reporter/At/Sig.
func (a *Advisory) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("reputation: bad reporter private key size")
	}
	pub := priv.Public().(ed25519.PublicKey)
	a.Reporter = []byte(pub)
	a.At = a.At.UTC().Truncate(time.Second)
	if a.At.IsZero() {
		a.At = time.Now().UTC().Truncate(time.Second)
	}
	a.Uptime = clip01(a.Uptime)
	a.Sig = ed25519.Sign(priv, a.bodyBytes())
	return nil
}

// Verify checks the reporter signature and field ranges.
func (a Advisory) Verify() error {
	if a.NodeID == "" {
		return errors.New("reputation: advisory empty node_id")
	}
	if a.Uptime < 0 || a.Uptime > 1 {
		return errors.New("reputation: advisory uptime out of range")
	}
	if a.AvgLatencyMs < 0 {
		return errors.New("reputation: advisory negative latency")
	}
	if a.Samples < 0 {
		return errors.New("reputation: advisory negative samples")
	}
	if len(a.Reporter) != ed25519.PublicKeySize {
		return errors.New("reputation: bad advisory reporter key size")
	}
	if len(a.Sig) != ed25519.SignatureSize {
		return errors.New("reputation: bad advisory signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(a.Reporter), a.bodyBytes(), a.Sig) {
		return errors.New("reputation: advisory signature verification failed")
	}
	return nil
}

// Marshal renders the exchange format (JSON).
func (a Advisory) Marshal() ([]byte, error) {
	if err := a.Verify(); err != nil {
		return nil, err
	}
	return json.Marshal(a)
}

// ParseAdvisory decodes and verifies one gossip message.
func ParseAdvisory(raw []byte) (Advisory, error) {
	var a Advisory
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return Advisory{}, fmt.Errorf("reputation: bad advisory: %w", err)
	}
	if err := a.Verify(); err != nil {
		return Advisory{}, err
	}
	return a, nil
}
