// Wallet connection for explicit payments.
//
// Two ways to reach the user's DERO:
//
//   - RPC:  a local wallet JSON-RPC server (optionally behind
//     `--rpc-login user:pass`). VeilNet reads address and balance and
//     builds transfers; nothing is submitted without approval.
//   - XSWD: the wallet-to-dApp socket. The WALLET renders every prompt;
//     VeilNet only asks. This is the recommended mode because approval
//     happens in software VeilNet does not control.
//
// Binding rules kept here: no auto-spend, no seed or key ever leaves
// the wallet, credentials never leave the configured loopback endpoint,
// and a wallet-less client stays fully usable (demo and unpaid nodes).
package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dero-veilnet/veilnet/internal/config"
	"github.com/dero-veilnet/veilnet/internal/dero"
	"github.com/dero-veilnet/veilnet/internal/events"
)

// walletProbeTimeout bounds RPC address/balance reads. XSWD calls get
// their own, much longer budget because a human clicks Approve.
const walletProbeTimeout = 10 * time.Second

// WalletStatus is the observable wallet state for UI/CLI. Secrets are
// never included.
type WalletStatus struct {
	Mode         string // NONE|RPC|XSWD
	Connected    bool
	Endpoint     string
	Address      string
	BalanceDero  float64
	UnlockedDero float64
	Network      string
	// Error is the last connect/refresh failure, in user-facing words.
	Error     string
	CheckedAt time.Time
}

// WalletConnectSpec is the connect request from the UI. Password is
// write-only: it is stored in config and never echoed back.
type WalletConnectSpec struct {
	Mode     string `json:"mode"`
	Endpoint string `json:"endpoint"`
	User     string `json:"user"`
	Password string `json:"password"`
	AppName  string `json:"app_name"`
	// Persist writes the (non-secret) connection settings to the config
	// file so the next launch reconnects without retyping.
	Persist bool `json:"persist"`
}

// walletConn holds the live connection, whichever transport it uses.
type walletConn struct {
	mode     string
	endpoint string
	rpc      dero.WalletClient
	xswd     *dero.XSWDClient
}

// WalletStatus reports the current wallet connection.
func (a *App) WalletStatus() WalletStatus {
	a.mu.RLock()
	conn := a.wallet
	cached := a.walletState
	network := a.cfg.Dero.Network
	cfgMode := a.cfg.Wallet.Mode
	a.mu.RUnlock()

	if conn == nil {
		mode := cfgMode
		if mode == "" {
			mode = config.WalletModeNone
		}
		return WalletStatus{
			Mode:      mode,
			Connected: false,
			Network:   network,
			Error:     cached.Error,
			CheckedAt: cached.CheckedAt,
		}
	}
	cached.Mode = conn.mode
	cached.Endpoint = conn.endpoint
	cached.Network = network
	cached.Connected = true
	if conn.mode == config.WalletModeXSWD && conn.xswd != nil {
		cached.Connected = conn.xswd.Connected()
	}
	return cached
}

// RefreshWallet re-reads address and balance from the live connection.
// It never spends. A failure is recorded in Status.Error, not returned
// as a fatal error, so the UI can keep rendering.
func (a *App) RefreshWallet() WalletStatus {
	a.mu.RLock()
	conn := a.wallet
	a.mu.RUnlock()
	if conn == nil {
		return a.WalletStatus()
	}
	st, err := a.probeWallet(conn)
	a.mu.Lock()
	if err != nil {
		a.walletState.Error = walletErrorText(err)
		a.walletState.CheckedAt = time.Now().UTC()
	} else {
		a.walletState = st
	}
	a.mu.Unlock()
	return a.WalletStatus()
}

// ConnectWallet opens the wallet connection described by spec. It
// replaces any existing connection. Nothing is spent; the call only
// authenticates and reads address + balance.
func (a *App) ConnectWallet(spec WalletConnectSpec) (WalletStatus, error) {
	mode := strings.ToUpper(strings.TrimSpace(spec.Mode))
	if mode == "" {
		mode = config.WalletModeNone
	}
	if mode == config.WalletModeNone {
		if err := a.DisconnectWallet(); err != nil {
			return a.WalletStatus(), err
		}
		if spec.Persist {
			if err := a.persistWallet(spec, mode); err != nil {
				return a.WalletStatus(), err
			}
		}
		return a.WalletStatus(), nil
	}

	a.mu.RLock()
	cur := a.cfg.Wallet
	a.mu.RUnlock()

	// Blank fields fall back to what is already configured, so the UI
	// can re-connect without re-sending a stored password.
	endpoint := firstNonEmpty(spec.Endpoint, modeEndpoint(cur, mode))
	user := firstNonEmpty(spec.User, cur.User)
	pass := spec.Password
	if pass == "" || pass == "***" {
		pass = cur.Password
	}
	appName := firstNonEmpty(spec.AppName, cur.AppName, "VeilNet")

	var conn *walletConn
	var err error
	switch mode {
	case config.WalletModeRPC:
		conn, err = a.dialWalletRPC(endpoint, user, pass)
	case config.WalletModeXSWD:
		conn, err = a.dialWalletXSWD(endpoint, appName)
	default:
		err = fmt.Errorf("unknown wallet mode %q", mode)
	}
	if err != nil {
		a.mu.Lock()
		a.walletState = WalletStatus{Mode: mode, Endpoint: endpoint, Error: walletErrorText(err), CheckedAt: time.Now().UTC()}
		a.mu.Unlock()
		return a.WalletStatus(), err
	}

	st, perr := a.probeWallet(conn)
	if perr != nil {
		closeWallet(conn)
		a.mu.Lock()
		a.walletState = WalletStatus{Mode: mode, Endpoint: endpoint, Error: walletErrorText(perr), CheckedAt: time.Now().UTC()}
		a.mu.Unlock()
		return a.WalletStatus(), perr
	}

	a.mu.Lock()
	old := a.wallet
	a.wallet = conn
	a.walletState = st
	a.mu.Unlock()
	if old != nil {
		closeWallet(old)
	}

	if spec.Persist {
		persisted := spec
		persisted.Endpoint = endpoint
		persisted.User = user
		persisted.Password = pass
		persisted.AppName = appName
		if err := a.persistWallet(persisted, mode); err != nil {
			return a.WalletStatus(), err
		}
	}
	events.Publish(events.DERO_CONNECTED, "wallet:"+mode)
	return a.WalletStatus(), nil
}

// DisconnectWallet drops the connection. Stored settings are kept so
// the user can reconnect with one click; only the live session ends.
func (a *App) DisconnectWallet() error {
	a.mu.Lock()
	conn := a.wallet
	a.wallet = nil
	a.walletState = WalletStatus{Mode: config.WalletModeNone, CheckedAt: time.Now().UTC()}
	a.mu.Unlock()
	if conn == nil {
		return nil
	}
	err := closeWallet(conn)
	events.Publish(events.DERO_DISCONNECTED, "wallet")
	return err
}

// Wallet returns the live RPC client, or nil when no RPC wallet is
// connected. Payment code uses this to build transfers.
func (a *App) Wallet() dero.WalletClient {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.wallet == nil {
		return nil
	}
	return a.wallet.rpc
}

// WalletBridge returns the live XSWD bridge, or nil when none is
// connected. Payment code uses this to ask the wallet to send.
func (a *App) WalletBridge() dero.XSWDConnector {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.wallet == nil || a.wallet.xswd == nil {
		return nil
	}
	return a.wallet.xswd
}

// PayApproved sends amountDero to dest through the connected wallet and
// records the receipt.
//
// This is the ONLY place VeilNet moves DERO, and it runs only after the
// user approved the amount in the VeilNet dialog. In XSWD mode the
// wallet asks a second time, in its own window; a refusal comes back as
// dero.ErrDenied and nothing is spent.
func (a *App) PayApproved(dest string, amountDero float64) (string, error) {
	if dest == "" {
		return "", errors.New("payment destination required")
	}
	if amountDero <= 0 {
		return "", errors.New("payment amount must be greater than zero")
	}
	a.mu.RLock()
	conn := a.wallet
	pending := a.pendingApproval
	maxPerHour := a.cfg.Payments.MaxPerHourDero
	network := a.cfg.Dero.Network
	a.mu.RUnlock()

	if conn == nil {
		return "", errors.New("no wallet connected: open the Wallet screen and connect over RPC or XSWD")
	}
	if !pending {
		return "", errors.New("no approved payment is pending: request approval first")
	}
	if maxPerHour > 0 && amountDero > maxPerHour {
		return "", fmt.Errorf("amount %.5f DERO exceeds the %.5f DERO/h budget cap", amountDero, maxPerHour)
	}

	atomic := dero.ToAtomic(amountDero)
	if atomic <= 0 {
		return "", errors.New("payment amount rounds to zero atomic units")
	}

	var txid string
	var err error
	switch {
	case conn.xswd != nil:
		txid, err = conn.xswd.RequestTransfer(context.Background(), dest, uint64(atomic))
	case conn.rpc != nil:
		var unsigned dero.UnsignedTransfer
		unsigned, err = conn.rpc.BuildTransfer(
			dero.TransferRequest{Destination: dest, AmountAtomic: uint64(atomic)},
			dero.Network(network))
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), walletProbeTimeout)
			txid, err = conn.rpc.SubmitTransfer(ctx, unsigned)
			cancel()
		}
	default:
		return "", errors.New("no wallet transport")
	}
	if err != nil {
		return "", err
	}
	if err := a.ConfirmPayment(amountDero, txid); err != nil {
		return txid, err
	}
	a.RefreshWallet()
	return txid, nil
}

// ---- transports ----

func (a *App) dialWalletRPC(endpoint, user, pass string) (*walletConn, error) {
	if endpoint == "" {
		return nil, errors.New("wallet RPC endpoint required")
	}
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		return nil, errors.New("wallet RPC endpoint must start with http:// or https://")
	}
	c := dero.NewWalletClientAuth(endpoint, user, pass)
	return &walletConn{mode: config.WalletModeRPC, endpoint: endpoint, rpc: c}, nil
}

func (a *App) dialWalletXSWD(endpoint, appName string) (*walletConn, error) {
	cfg := dero.NewXSWDConfig(endpoint, appName)
	c := dero.NewXSWDClient()
	// The handshake blocks on the user's own Approve click in the
	// wallet, so it gets the connector's generous budget, not ours.
	if err := c.Connect(context.Background(), cfg); err != nil {
		return nil, err
	}
	return &walletConn{mode: config.WalletModeXSWD, endpoint: cfg.Endpoint, xswd: c}, nil
}

// probeWallet reads address and balance. Read-only: it never spends.
func (a *App) probeWallet(conn *walletConn) (WalletStatus, error) {
	a.mu.RLock()
	network := a.cfg.Dero.Network
	a.mu.RUnlock()

	st := WalletStatus{
		Mode: conn.mode, Endpoint: conn.endpoint, Connected: true,
		Network: network, CheckedAt: time.Now().UTC(),
	}

	switch {
	case conn.rpc != nil:
		ctx, cancel := context.WithTimeout(context.Background(), walletProbeTimeout)
		defer cancel()
		addr, err := conn.rpc.GetAddress(ctx)
		if err != nil {
			return WalletStatus{}, err
		}
		st.Address = addr
		bal, err := conn.rpc.GetBalance(ctx)
		if err != nil {
			return WalletStatus{}, err
		}
		st.BalanceDero = dero.FromAtomic(int64(bal.Balance))
		st.UnlockedDero = dero.FromAtomic(int64(bal.UnlockedBalance))
	case conn.xswd != nil:
		ctx := context.Background()
		addr, err := conn.xswd.GetAddress(ctx)
		if err != nil {
			return WalletStatus{}, err
		}
		st.Address = addr
		bal, err := conn.xswd.GetBalance(ctx)
		if err != nil {
			// Balance permission may be refused separately from
			// address; that is not a connection failure.
			if !errors.Is(err, dero.ErrDenied) {
				return WalletStatus{}, err
			}
			st.Error = "wallet did not share the balance (address only)"
		} else {
			st.BalanceDero = dero.FromAtomic(int64(bal.Balance))
			st.UnlockedDero = dero.FromAtomic(int64(bal.UnlockedBalance))
		}
	default:
		return WalletStatus{}, errors.New("no wallet transport")
	}
	return st, nil
}

func closeWallet(conn *walletConn) error {
	if conn == nil || conn.xswd == nil {
		return nil
	}
	return conn.xswd.Close()
}

// persistWallet writes the connection settings into the config file.
func (a *App) persistWallet(spec WalletConnectSpec, mode string) error {
	a.mu.RLock()
	cfg := a.cfg
	a.mu.RUnlock()
	cfg.Wallet.Mode = mode
	if spec.AppName != "" {
		cfg.Wallet.AppName = spec.AppName
	}
	switch mode {
	case config.WalletModeRPC:
		if spec.Endpoint != "" {
			cfg.Wallet.Endpoint = spec.Endpoint
		}
		cfg.Wallet.User = spec.User
		if spec.Password != "" && spec.Password != "***" {
			cfg.Wallet.Password = spec.Password
		}
	case config.WalletModeXSWD:
		if spec.Endpoint != "" {
			cfg.Wallet.XSWDEndpoint = spec.Endpoint
		}
	}
	return a.UpdateConfig(cfg, "")
}

// AutoConnectWallet reconnects a previously saved RPC wallet at
// startup. XSWD is never auto-connected: that would pop a prompt in the
// user's wallet without the user asking for it.
func (a *App) AutoConnectWallet() {
	a.mu.RLock()
	w := a.cfg.Wallet
	a.mu.RUnlock()
	if w.Mode != config.WalletModeRPC || w.Endpoint == "" {
		return
	}
	_, _ = a.ConnectWallet(WalletConnectSpec{
		Mode: config.WalletModeRPC, Endpoint: w.Endpoint,
		User: w.User, Password: w.Password,
	})
}

// ---- helpers ----

func modeEndpoint(w config.WalletConfig, mode string) string {
	if mode == config.WalletModeXSWD {
		if w.XSWDEndpoint != "" {
			return w.XSWDEndpoint
		}
		return config.DefaultXSWDEndpoint
	}
	return w.Endpoint
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// walletErrorText turns a transport error into words a user can act on.
func walletErrorText(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, dero.ErrDenied):
		return "The wallet refused the request. Nothing was spent. Approve VeilNet in your wallet and try again."
	case dero.IsUnavailable(err):
		return "The wallet did not answer. Check it is running and the endpoint is right: " + err.Error()
	case strings.Contains(strings.ToLower(err.Error()), "rpc-login"):
		return "The wallet needs a user and password (its --rpc-login value)."
	default:
		return err.Error()
	}
}
