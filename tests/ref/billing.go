package ref

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Quote computes a pro-rata session price from the node's hourly rate.
// Amounts are integer atomic units (1 DERO = 1e12 units); hours may be
// fractional. Negative or NaN inputs are rejected.
func Quote(pricePerHour float64, duration time.Duration) (uint64, error) {
	if pricePerHour < 0 || duration < 0 {
		return 0, errors.New("ref: negative billing input rejected")
	}
	hours := duration.Hours()
	dero := pricePerHour * hours
	units := uint64(dero * 1e12)
	return units, nil
}

// Receipt is a node-signed proof of payment. It carries NO secret key
// material: only ids, amounts, and an HMAC tag under the node's receipt key.
// (Stdlib HMAC-SHA256 is message authentication, not custom crypto.)
type Receipt struct {
	ReceiptID string
	NodeID    string
	SessionID string
	Amount    uint64
	IssuedAt  time.Time
	Tag       string // hex HMAC over the canonical fields
}

func receiptMAC(key []byte, r Receipt) string {
	msg := fmt.Sprintf("%s|%s|%s|%d|%d",
		r.ReceiptID, r.NodeID, r.SessionID, r.Amount, r.IssuedAt.UTC().Unix())
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

// SignReceipt issues a receipt. key is the node's local receipt key and must
// never leave the node; it is never serialized into the receipt.
func SignReceipt(key []byte, receiptID, nodeID, sessionID string, amount uint64, at time.Time) (Receipt, error) {
	if len(key) < 16 {
		return Receipt{}, errors.New("ref: receipt key too short")
	}
	if receiptID == "" || nodeID == "" || sessionID == "" {
		return Receipt{}, errors.New("ref: receipt ids required")
	}
	r := Receipt{
		ReceiptID: receiptID, NodeID: nodeID, SessionID: sessionID,
		Amount: amount, IssuedAt: at.UTC(),
	}
	r.Tag = receiptMAC(key, r)
	return r, nil
}

// VerifyReceipt rejects any receipt whose fields were altered after signing.
func VerifyReceipt(key []byte, r Receipt) error {
	if subtleCompare(receiptMAC(key, r), r.Tag) != 1 {
		return errors.New("ref: receipt tampered or mis-signed")
	}
	return nil
}

func subtleCompare(a, b string) int {
	if len(a) != len(b) {
		return 0
	}
	diff := 0
	for i := range a {
		diff |= int(a[i] ^ b[i])
	}
	if diff == 0 {
		return 1
	}
	return 0
}
