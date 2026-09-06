// DevMock + Testnet/Mainnet switch and outage helpers.
//
// DevMock (MockDaemonClient + MockWalletClient) implements the same
// DaemonClient / WalletClient interfaces with canned state and zero
// real-DERO spend. Unsupported RPCs are not invented here: anything
// outside the documented surface fails loudly through MockAdapter so
// tests cannot mistake a stub for chain truth.
//
// Outage policy (binding): a DERO outage NEVER kills established
// tunnels. Only operations that need fresh chain truth fail:
// prepaid funding, settlement submission, registry mirror writes.
// Distinguish with IsUnavailable; established data-plane sessions
// continue on their existing tokens until token expiry.
package dero

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/dero-veilnet/veilnet/internal/events"
)

// MockDaemonClient is a canned DaemonClient. Flip Fail to simulate an
// outage (calls return ErrDeroUnavailable).
type MockDaemonClient struct {
	mu       sync.Mutex
	Height   HeightInfo
	Info     ChainInfo
	Fail     bool
	endpoint string
}

// NewMockDaemon returns a mock at height 1000 on "devmock" network.
func NewMockDaemon() *MockDaemonClient {
	return &MockDaemonClient{
		Height:   HeightInfo{Height: 1000, StableHeight: 998, TopoHeight: 1000},
		Info:     ChainInfo{Height: 1000, StableHeight: 998, TopoHeight: 1000, Network: "devmock", Version: "mock"},
		endpoint: DefaultEndpoints(NetworkDevMock).Daemon,
	}
}

// Endpoint returns the mock daemon URL.
func (m *MockDaemonClient) Endpoint() string { return m.endpoint }

// GetHeight implements DaemonClient.
func (m *MockDaemonClient) GetHeight(ctx context.Context) (HeightInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail {
		return HeightInfo{}, ErrDeroUnavailable
	}
	return m.Height, nil
}

// GetInfo implements DaemonClient.
func (m *MockDaemonClient) GetInfo(ctx context.Context) (ChainInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail {
		return ChainInfo{}, ErrDeroUnavailable
	}
	return m.Info, nil
}

// MockWalletClient is a canned WalletClient with zero real spend.
// Submits return synthetic txids ("mock-tx-N") and are recorded for
// assertions. Seeds/keys never exist here: there is nothing to leak.
type MockWalletClient struct {
	mu       sync.Mutex
	BalanceV Balance
	Address  string
	Fail     bool
	Submits  []UnsignedTransfer
	Invokes  []UnsignedInvoke
	endpoint string
	txSeq    int
}

// NewMockWallet returns a mock funded with 100 DERO for demo flows.
func NewMockWallet() *MockWalletClient {
	return &MockWalletClient{
		BalanceV: Balance{Balance: 100 * AtomicPerDero, UnlockedBalance: 100 * AtomicPerDero},
		Address:  "deto1mockwallet0000000000000000000000000000000000",
		endpoint: DefaultEndpoints(NetworkDevMock).Wallet,
	}
}

// Endpoint returns the mock wallet URL.
func (m *MockWalletClient) Endpoint() string { return m.endpoint }

// GetBalance implements WalletClient.
func (m *MockWalletClient) GetBalance(ctx context.Context) (Balance, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail {
		return Balance{}, ErrDeroUnavailable
	}
	return m.BalanceV, nil
}

// GetAddress implements WalletClient.
func (m *MockWalletClient) GetAddress(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail {
		return "", ErrDeroUnavailable
	}
	return m.Address, nil
}

// BuildTransfer implements WalletClient (no spend, mock or not).
func (m *MockWalletClient) BuildTransfer(req TransferRequest, net Network) (UnsignedTransfer, error) {
	if req.Destination == "" {
		return UnsignedTransfer{}, errors.New("dero: empty destination")
	}
	if req.AmountAtomic == 0 {
		return UnsignedTransfer{}, errors.New("dero: zero amount")
	}
	return UnsignedTransfer{Destination: req.Destination, AmountAtomic: req.AmountAtomic, Network: net}, nil
}

// SubmitTransfer implements WalletClient, recording the spend.
func (m *MockWalletClient) SubmitTransfer(ctx context.Context, u UnsignedTransfer) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail {
		return "", ErrDeroUnavailable
	}
	m.txSeq++
	m.Submits = append(m.Submits, u)
	return fmt.Sprintf("mock-tx-%d", m.txSeq), nil
}

// BuildInvoke implements WalletClient.
func (m *MockWalletClient) BuildInvoke(scid, entrypoint string, args []SCArg, net Network) (UnsignedInvoke, error) {
	if scid == "" || entrypoint == "" {
		return UnsignedInvoke{}, errors.New("dero: scid and entrypoint required")
	}
	return UnsignedInvoke{SCID: scid, Entrypoint: entrypoint, Args: args, Network: net}, nil
}

// SubmitInvoke implements WalletClient, recording the call.
func (m *MockWalletClient) SubmitInvoke(ctx context.Context, u UnsignedInvoke) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail {
		return "", ErrDeroUnavailable
	}
	m.txSeq++
	m.Invokes = append(m.Invokes, u)
	return fmt.Sprintf("mock-tx-%d", m.txSeq), nil
}

// GetTransferByTXID implements WalletClient for mock txids only.
func (m *MockWalletClient) GetTransferByTXID(ctx context.Context, txid string) (TransferInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail {
		return TransferInfo{}, ErrDeroUnavailable
	}
	return TransferInfo{TXID: txid, Height: m.HeightSafe(), TopoHeight: m.HeightSafe()}, nil
}

// HeightSafe reads the mock height without locking assumptions.
func (m *MockWalletClient) HeightSafe() uint64 { return 1000 }

// MockAdapter is the explicit boundary for unsupported calls: any RPC
// outside the documented surface used by VeilNet must go through here
// and fail loudly, so no invented endpoint ever looks real.
type MockAdapter struct {
	Method string
}

// Call always fails: the method is unsupported by design.
func (a MockAdapter) Call(ctx context.Context) error {
	return fmt.Errorf("dero: RPC %q is not part of the VeilNet DERO surface (see docs/DERO_INTEGRATION.md)", a.Method)
}

// ReportStatus fans DERO_CONNECTED / DERO_DISCONNECTED on the process
// event bus. Call with available=false on IsUnavailable, true on the
// next successful RPC. It never touches tunnels itself: subscribers
// (client UI, node controller) decide, with the binding rule that
// established tunnels survive an outage.
func ReportStatus(available bool) {
	if available {
		events.Publish(events.DERO_CONNECTED, nil)
		return
	}
	events.Publish(events.DERO_DISCONNECTED, nil)
}

// RequireFreshChain is the fail-closed gate for operations that need
// live chain truth (prepaid funding, settlement). Established sessions
// MUST NOT pass through it: they continue until token expiry.
func RequireFreshChain(err error) error {
	if err == nil {
		return nil
	}
	if IsUnavailable(err) {
		return fmt.Errorf("dero: chain unreachable, fresh auth unavailable (established tunnels continue): %w", err)
	}
	return err
}
