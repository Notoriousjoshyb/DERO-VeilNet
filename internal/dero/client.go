// Package dero is the DERO control-plane client.
//
// DERO NEVER carries user traffic: it carries registry writes, prepaid
// funding and periodic settlement only. Secret keys are NEVER put
// on-chain and the wallet NEVER auto-spends: every transfer is built as
// an unsigned payload first and submitted only after explicit user
// approval (see Approval in payments).
//
// A DERO outage NEVER kills established tunnels: tunnels fail closed
// only where fresh DERO auth is required (new prepaid funding, new
// settlement). Use IsUnavailable to branch on transport failure and
// ReportStatus to fan DERO_CONNECTED / DERO_DISCONNECTED events.
package dero

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"
)

// Network selects the DERO endpoint set. DevMock performs zero real-DERO
// spend and is the default for tests and `--demo`.
type Network string

const (
	NetworkDevMock Network = "devmock"
	NetworkTestnet Network = "testnet"
	NetworkMainnet Network = "mainnet"
)

// Endpoints are base URLs (scheme://host:port, no trailing path).
type Endpoints struct {
	Daemon string
	Wallet string
}

// DefaultEndpoints returns per-network defaults. Daemon ports follow the
// documented derod examples (10102); wallet ports follow the Stargate
// wallet RPC default (40403). DevMock ports are localhost-only and
// never routable to a real chain.
func DefaultEndpoints(n Network) Endpoints {
	switch n {
	case NetworkMainnet:
		return Endpoints{
			Daemon: "http://127.0.0.1:10102",
			Wallet: "http://127.0.0.1:40403",
		}
	case NetworkTestnet:
		return Endpoints{
			Daemon: "http://127.0.0.1:10102",
			Wallet: "http://127.0.0.1:40403",
		}
	default:
		return Endpoints{
			Daemon: "http://127.0.0.1:19092",
			Wallet: "http://127.0.0.1:19093",
		}
	}
}

// AtomicPerDero is the Stargate atomic-unit rate used by the documented
// wallet RPC examples: 100000 atomic units = 1 DERO.
const AtomicPerDero = 100_000

// ToAtomic converts whole DERO to atomic units. Negative input yields 0.
func ToAtomic(dero float64) int64 {
	if dero <= 0 || math.IsNaN(dero) || math.IsInf(dero, 0) {
		return 0
	}
	return int64(math.Round(dero * AtomicPerDero))
}

// FromAtomic converts atomic units back to whole DERO.
func FromAtomic(a int64) float64 {
	return float64(a) / AtomicPerDero
}

// ErrDeroUnavailable marks transport/RPC failure against daemon or
// wallet. Callers MUST treat it as "chain unknown", never as "chain
// says no": established tunnels continue; only fresh DERO auth fails.
var ErrDeroUnavailable = errors.New("dero: endpoint unavailable")

// IsUnavailable reports whether err is (or wraps) ErrDeroUnavailable.
func IsUnavailable(err error) bool {
	return errors.Is(err, ErrDeroUnavailable)
}

// HeightInfo mirrors the fields VeilNet reads from DERO.GetHeight.
type HeightInfo struct {
	Height       uint64
	StableHeight uint64
	TopoHeight   uint64
}

// ChainInfo mirrors the fields VeilNet reads from DERO.GetInfo.
type ChainInfo struct {
	Height       uint64
	StableHeight uint64
	TopoHeight   uint64
	Network      string
	Version      string
	PeerCount    int
}

// DaemonClient reads chain state. It never spends.
type DaemonClient interface {
	GetHeight(ctx context.Context) (HeightInfo, error)
	GetInfo(ctx context.Context) (ChainInfo, error)
	Endpoint() string
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// HTTPDaemonClient speaks daemon JSON-RPC at <base>/json_rpc using the
// documented Stargate methods DERO.GetHeight and DERO.GetInfo.
// See docs/DERO_INTEGRATION.md for sources.
type HTTPDaemonClient struct {
	base   string
	client *http.Client
}

// NewDaemonClient builds an HTTP daemon client for base (no /json_rpc).
func NewDaemonClient(base string) *HTTPDaemonClient {
	return &HTTPDaemonClient{
		base:   base,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// Endpoint returns the configured daemon base URL.
func (c *HTTPDaemonClient) Endpoint() string { return c.base }

func (c *HTTPDaemonClient) call(ctx context.Context, method string, out any) error {
	body, _ := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: method})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/json_rpc", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDeroUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDeroUnavailable, err)
	}
	defer resp.Body.Close()
	var r rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return fmt.Errorf("%w: %v", ErrDeroUnavailable, err)
	}
	if r.Error != nil {
		return fmt.Errorf("dero: daemon %s: %s", method, r.Error.Message)
	}
	if out != nil {
		if err := json.Unmarshal(r.Result, out); err != nil {
			return fmt.Errorf("dero: decode %s: %w", method, err)
		}
	}
	return nil
}

// GetHeight calls DERO.GetHeight.
func (c *HTTPDaemonClient) GetHeight(ctx context.Context) (HeightInfo, error) {
	var v struct {
		Height       uint64 `json:"height"`
		StableHeight uint64 `json:"stableheight"`
		TopoHeight   uint64 `json:"topoheight"`
	}
	if err := c.call(ctx, "DERO.GetHeight", &v); err != nil {
		return HeightInfo{}, err
	}
	return HeightInfo{Height: v.Height, StableHeight: v.StableHeight, TopoHeight: v.TopoHeight}, nil
}

// GetInfo calls DERO.GetInfo.
func (c *HTTPDaemonClient) GetInfo(ctx context.Context) (ChainInfo, error) {
	var v struct {
		Height       uint64 `json:"height"`
		StableHeight uint64 `json:"stableheight"`
		TopoHeight   uint64 `json:"topoheight"`
		Network      string `json:"network"`
		Version      string `json:"version"`
		PeerCount    int    `json:"peer_count"`
	}
	if err := c.call(ctx, "DERO.GetInfo", &v); err != nil {
		return ChainInfo{}, err
	}
	return ChainInfo{
		Height: v.Height, StableHeight: v.StableHeight, TopoHeight: v.TopoHeight,
		Network: v.Network, Version: v.Version, PeerCount: v.PeerCount,
	}, nil
}

// Balance is a wallet balance in atomic units.
type Balance struct {
	Balance         uint64
	UnlockedBalance uint64
}

// TransferRequest asks the wallet to BUILD (not send) a transfer.
type TransferRequest struct {
	Destination   string
	AmountAtomic uint64
}

// UnsignedTransfer is a built, unsubmitted transfer. Submitting it
// requires the explicit user approval handled in internal/payments.
type UnsignedTransfer struct {
	Destination   string
	AmountAtomic uint64
	Network      Network
}

// SCArg is one sc_rpc argument for a contract invocation.
type SCArg struct {
	Name     string
	DataType string // "S" string, "U" Uint64, "H" hash/SCID
	Value    any
}

// UnsignedInvoke is a built, unsubmitted contract call.
type UnsignedInvoke struct {
	SCID       string
	Entrypoint string
	Args       []SCArg
	Network    Network
}

// TransferInfo mirrors GetTransferbyTXID fields VeilNet reads back.
type TransferInfo struct {
	TXID       string
	Height     uint64
	TopoHeight uint64
	Incoming   bool
}

// WalletClient speaks the documented wallet JSON-RPC methods
// (GetBalance, GetAddress, GetHeight, GetTransferbyTXID, transfer,
// scinvoke). Build* methods NEVER touch the chain; Submit* methods are
// called only after explicit user approval. Seeds/keys are never
// exposed: the RPC server holds them and only txids cross the wire.
type WalletClient interface {
	GetBalance(ctx context.Context) (Balance, error)
	GetAddress(ctx context.Context) (string, error)
	BuildTransfer(req TransferRequest, net Network) (UnsignedTransfer, error)
	SubmitTransfer(ctx context.Context, u UnsignedTransfer) (string, error)
	BuildInvoke(scid, entrypoint string, args []SCArg, net Network) (UnsignedInvoke, error)
	SubmitInvoke(ctx context.Context, u UnsignedInvoke) (string, error)
	GetTransferByTXID(ctx context.Context, txid string) (TransferInfo, error)
	Endpoint() string
}

// HTTPWalletClient implements WalletClient over wallet JSON-RPC.
type HTTPWalletClient struct {
	base   string
	client *http.Client
	auth   creds
}

// NewWalletClient builds an HTTP wallet client for base (no /json_rpc).
func NewWalletClient(base string) *HTTPWalletClient {
	return &HTTPWalletClient{
		base:   base,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// NewWalletClientAuth builds a wallet client that answers the
// `--rpc-login` challenge with user/pass. Empty credentials behave
// exactly like NewWalletClient.
func NewWalletClientAuth(base, user, pass string) *HTTPWalletClient {
	c := NewWalletClient(base)
	c.auth = creds{user: user, pass: pass}
	return c
}

// Endpoint returns the configured wallet base URL.
func (c *HTTPWalletClient) Endpoint() string { return c.base }

func (c *HTTPWalletClient) call(ctx context.Context, method string, params any, out any) error {
	body, _ := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	newReq := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/json_rpc", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	}
	req, err := newReq()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDeroUnavailable, err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDeroUnavailable, err)
	}
	// Answer a `--rpc-login` challenge once, using the scheme the
	// server actually asked for.
	if resp.StatusCode == http.StatusUnauthorized && !c.auth.empty() {
		retry, rerr := newReq()
		if rerr != nil {
			resp.Body.Close()
			return fmt.Errorf("%w: %v", ErrDeroUnavailable, rerr)
		}
		ok := c.auth.applyRetryAuth(retry, resp)
		resp.Body.Close()
		if !ok {
			return errors.New("dero: wallet rejected credentials")
		}
		resp, err = c.client.Do(retry)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrDeroUnavailable, err)
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return errors.New("dero: wallet requires rpc-login credentials")
	}
	var r rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return fmt.Errorf("%w: %v", ErrDeroUnavailable, err)
	}
	if r.Error != nil {
		return fmt.Errorf("dero: wallet %s: %s", method, r.Error.Message)
	}
	if out != nil {
		if err := json.Unmarshal(r.Result, out); err != nil {
			return fmt.Errorf("dero: decode %s: %w", method, err)
		}
	}
	return nil
}

// GetBalance calls GetBalance. Amounts are atomic units.
func (c *HTTPWalletClient) GetBalance(ctx context.Context) (Balance, error) {
	var v struct {
		Balance         uint64 `json:"balance"`
		UnlockedBalance uint64 `json:"unlocked_balance"`
	}
	if err := c.call(ctx, "GetBalance", map[string]any{}, &v); err != nil {
		return Balance{}, err
	}
	return Balance{Balance: v.Balance, UnlockedBalance: v.UnlockedBalance}, nil
}

// GetAddress calls GetAddress.
func (c *HTTPWalletClient) GetAddress(ctx context.Context) (string, error) {
	var v struct {
		Address string `json:"address"`
	}
	if err := c.call(ctx, "GetAddress", map[string]any{}, &v); err != nil {
		return "", err
	}
	return v.Address, nil
}

// BuildTransfer validates locally and returns an unsigned payload.
// No RPC is issued: nothing is spent until SubmitTransfer.
func (c *HTTPWalletClient) BuildTransfer(req TransferRequest, net Network) (UnsignedTransfer, error) {
	if req.Destination == "" {
		return UnsignedTransfer{}, errors.New("dero: empty destination")
	}
	if req.AmountAtomic == 0 {
		return UnsignedTransfer{}, errors.New("dero: zero amount")
	}
	return UnsignedTransfer{Destination: req.Destination, AmountAtomic: req.AmountAtomic, Network: net}, nil
}

// SubmitTransfer sends a previously approved transfer via `transfer`.
func (c *HTTPWalletClient) SubmitTransfer(ctx context.Context, u UnsignedTransfer) (string, error) {
	if u.Network != NetworkTestnet && u.Network != NetworkMainnet {
		return "", errors.New("dero: refusing to submit non-testnet/mainnet transfer (use the mock adapter for dev)")
	}
	params := map[string]any{
		"destination": u.Destination,
		"amount":      u.AmountAtomic,
		"ringsize":    32,
	}
	var v struct {
		TXID string `json:"txid"`
	}
	if err := c.call(ctx, "transfer", params, &v); err != nil {
		return "", err
	}
	return v.TXID, nil
}

// BuildInvoke validates locally and returns an unsigned contract call.
func (c *HTTPWalletClient) BuildInvoke(scid, entrypoint string, args []SCArg, net Network) (UnsignedInvoke, error) {
	if scid == "" || entrypoint == "" {
		return UnsignedInvoke{}, errors.New("dero: scid and entrypoint required")
	}
	return UnsignedInvoke{SCID: scid, Entrypoint: entrypoint, Args: args, Network: net}, nil
}

// SubmitInvoke sends a previously approved call via `scinvoke`.
func (c *HTTPWalletClient) SubmitInvoke(ctx context.Context, u UnsignedInvoke) (string, error) {
	if u.Network != NetworkTestnet && u.Network != NetworkMainnet {
		return "", errors.New("dero: refusing to submit non-testnet/mainnet invoke (use the mock adapter for dev)")
	}
	rpc := make([]map[string]any, 0, len(u.Args)+1)
	rpc = append(rpc, map[string]any{"name": "entrypoint", "datatype": "S", "value": u.Entrypoint})
	for _, a := range u.Args {
		rpc = append(rpc, map[string]any{"name": a.Name, "datatype": a.DataType, "value": a.Value})
	}
	params := map[string]any{"scid": u.SCID, "ringsize": 2, "sc_rpc": rpc}
	var v struct {
		TXID string `json:"txid"`
	}
	if err := c.call(ctx, "scinvoke", params, &v); err != nil {
		return "", err
	}
	return v.TXID, nil
}

// GetTransferByTXID calls GetTransferbyTXID (exact documented casing).
func (c *HTTPWalletClient) GetTransferByTXID(ctx context.Context, txid string) (TransferInfo, error) {
	var v struct {
		Height     uint64 `json:"height"`
		TopoHeight uint64 `json:"topoheight"`
		Incoming   bool   `json:"incoming"`
	}
	if err := c.call(ctx, "GetTransferbyTXID", map[string]any{"txid": txid}, &v); err != nil {
		return TransferInfo{}, err
	}
	return TransferInfo{TXID: txid, Height: v.Height, TopoHeight: v.TopoHeight, Incoming: v.Incoming}, nil
}
