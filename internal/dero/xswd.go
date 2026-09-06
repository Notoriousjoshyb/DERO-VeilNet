// XSWD hook point: wallet-to-application bridge for user-approved spend.
//
// In production the spend approval dialog SHOULD route through the
// user's own wallet via XSWD (DERO wallet-to-dApp protocol) or the
// equivalent wallet bridge, so raw transfers are confirmed in the
// wallet UX, not just VeilNet's. Direct wallet JSON-RPC stays bound to
// localhost. This file is the seam: production code implements
// XSWDConnector against the wallet's XSWD endpoint, while DevMock and
// `--demo` use MockXSWD which auto-approves nothing (it records, the
// payments Approver decides).
package dero

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// XSWDConfig points at the wallet's XSWD bridge endpoint.
type XSWDConfig struct {
	// AppID is the dApp identifier presented to the wallet.
	AppID string
	// AppName is shown in the wallet approval prompt.
	AppName string
	// Endpoint is the XSWD websocket/HTTP bridge URL.
	Endpoint string
}

// XSWDConnector is the minimal wallet-bridge surface VeilNet needs.
// Full signing stays inside the wallet; VeilNet only requests.
type XSWDConnector interface {
	// Connect opens the bridge session for cfg.AppID.
	Connect(ctx context.Context, cfg XSWDConfig) error
	// Connected reports a live bridge session.
	Connected() bool
	// RequestTransfer asks the wallet to approve+send; the wallet may
	// refuse. The returned txid is empty on refusal with ErrDenied.
	RequestTransfer(ctx context.Context, dest string, amountAtomic uint64) (string, error)
	// Close ends the bridge session.
	Close() error
}

// ErrDenied means the user (or wallet) refused the request.
var ErrDenied = errors.New("dero: wallet denied request")

// MockXSWD records requests for tests and demo. It approves only when
// AutoApprove is true; otherwise it returns ErrDenied, mimicking a
// user refusing in the wallet UX.
type MockXSWD struct {
	mu          sync.Mutex
	AutoApprove bool
	Requests    []MockXSWDRequest
	connected   bool
	txSeq       int
}

// MockXSWDRequest is one recorded bridge request.
type MockXSWDRequest struct {
	Destination   string
	AmountAtomic uint64
}

// NewMockXSWD returns a disconnected bridge that denies by default.
func NewMockXSWD() *MockXSWD { return &MockXSWD{} }

// Connect implements XSWDConnector.
func (m *MockXSWD) Connect(ctx context.Context, cfg XSWDConfig) error {
	if cfg.AppID == "" {
		return errors.New("dero: XSWD AppID required")
	}
	m.mu.Lock()
	m.connected = true
	m.mu.Unlock()
	return nil
}

// Connected implements XSWDConnector.
func (m *MockXSWD) Connected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connected
}

// RequestTransfer implements XSWDConnector.
func (m *MockXSWD) RequestTransfer(ctx context.Context, dest string, amountAtomic uint64) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.connected {
		return "", errors.New("dero: XSWD not connected")
	}
	m.Requests = append(m.Requests, MockXSWDRequest{Destination: dest, AmountAtomic: amountAtomic})
	if !m.AutoApprove {
		return "", ErrDenied
	}
	m.txSeq++
	return fmt.Sprintf("mock-xswd-tx-%d", m.txSeq), nil
}

// Close implements XSWDConnector.
func (m *MockXSWD) Close() error {
	m.mu.Lock()
	m.connected = false
	m.mu.Unlock()
	return nil
}
