// Package ui is the VeilNet client frontend backend.
package ui

import (
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"

	"github.com/dero-veilnet/veilnet/internal/app"
	"github.com/dero-veilnet/veilnet/internal/config"
)

//go:embed frontend
var frontend embed.FS

// Provider is the data source behind the UI. *app.App implements it
// directly; the GUI uses a remote implementation over IPC when the
// privileged service owns the engine. The Wails v2 shell can bind any
// Provider (plain-Go methods, JSON-friendly types).
type Provider interface {
	State() app.ConnState
	ListNodes() ([]app.NodeInfo, error)
	Connect(nodeID string) error
	Disconnect() error
	Diagnose() app.Diagnostics
	Payment() app.PaymentInfo
	Config() config.ClientConfig
	UpdateConfig(cfg config.ClientConfig, savePath string) error
	BuildCircuit(entryID, exitID string) error
	AutoCircuit() error
	RotateCircuit() error
	RequestPaymentApproval()
	ConfirmPayment(amount float64, txid string) error
}

// Backend exposes app state and actions to the frontend.
type Backend struct {
	app Provider
}

// NewBackend wraps a.
func NewBackend(a Provider) *Backend { return &Backend{app: a} }

// Handler serves the embedded frontend plus the JSON API.
func (b *Backend) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(frontend, "frontend")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/state", b.handleState)
	mux.HandleFunc("/api/nodes", b.handleNodes)
	mux.HandleFunc("/api/connect", b.handleConnect)
	mux.HandleFunc("/api/disconnect", b.handleDisconnect)
	mux.HandleFunc("/api/diagnostics", b.handleDiagnostics)
	mux.HandleFunc("/api/payment", b.handlePayment)
	mux.HandleFunc("/api/config", b.handleConfig)
	mux.HandleFunc("/api/circuit", b.handleCircuit)
	mux.HandleFunc("/api/rotate", b.handleRotate)
	mux.HandleFunc("/api/guard", b.handleGuard)
	mux.HandleFunc("/api/approve-payment", b.handleApprove)
	mux.HandleFunc("/api/confirm-payment", b.handleConfirm)
	mux.HandleFunc("/api/wallet", b.handleWallet)
	mux.HandleFunc("/api/wallet/disconnect", b.handleWalletDisconnect)
	mux.HandleFunc("/api/wallet/pay", b.handleWalletPay)
	return mux
}

// WalletProvider is the optional wallet surface. Providers that cannot
// reach a wallet (a view-only GUI, for example) simply do not implement
// it and the wallet endpoints answer 501.
type WalletProvider interface {
	WalletStatus() app.WalletStatus
	ConnectWallet(spec app.WalletConnectSpec) (app.WalletStatus, error)
	DisconnectWallet() error
	RefreshWallet() app.WalletStatus
}

// walletPayer is implemented separately: a provider may expose status
// without being able to move funds.
type walletPayer interface {
	PayApproved(dest string, amountDero float64) (string, error)
}

func (b *Backend) walletProvider(w http.ResponseWriter) (WalletProvider, bool) {
	wp, ok := b.app.(WalletProvider)
	if !ok {
		writeErr(w, http.StatusNotImplemented,
			errors.New("wallet connect is not available from this client; start the VeilNet service"))
		return nil, false
	}
	return wp, true
}

// handleWallet reports wallet status (GET) or opens a connection
// (POST). Passwords travel one way only: they are never echoed back.
func (b *Backend) handleWallet(w http.ResponseWriter, r *http.Request) {
	wp, ok := b.walletProvider(w)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		if r.URL.Query().Get("refresh") == "1" {
			writeJSON(w, wp.RefreshWallet())
			return
		}
		writeJSON(w, wp.WalletStatus())
		return
	}
	var spec app.WalletConnectSpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		writeErr(w, 400, err)
		return
	}
	st, err := wp.ConnectWallet(spec)
	if err != nil {
		writeErr(w, 502, err)
		return
	}
	writeJSON(w, st)
}

func (b *Backend) handleWalletDisconnect(w http.ResponseWriter, r *http.Request) {
	wp, ok := b.walletProvider(w)
	if !ok {
		return
	}
	if err := wp.DisconnectWallet(); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, wp.WalletStatus())
}

// handleWalletPay sends an already-approved amount. The engine refuses
// unless an approval is pending, so this cannot become an auto-spend.
func (b *Backend) handleWalletPay(w http.ResponseWriter, r *http.Request) {
	payer, ok := b.app.(walletPayer)
	if !ok {
		writeErr(w, http.StatusNotImplemented, errors.New("this client cannot send payments"))
		return
	}
	var req struct {
		Destination string  `json:"destination"`
		AmountDero  float64 `json:"amount_dero"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	txid, err := payer.PayApproved(req.Destination, req.AmountDero)
	if err != nil {
		writeErr(w, 502, err)
		return
	}
	writeJSON(w, map[string]any{"txid": txid, "payment": b.app.Payment()})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func (b *Backend) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, b.app.State())
}

func (b *Backend) handleNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := b.app.ListNodes()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, nodes)
}

func (b *Backend) handleConnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NodeID string `json:"node_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := b.app.Connect(req.NodeID); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, b.app.State())
}

func (b *Backend) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if err := b.app.Disconnect(); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, b.app.State())
}

func (b *Backend) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, b.app.Diagnose())
}

func (b *Backend) handlePayment(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, b.app.Payment())
}

func (b *Backend) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, b.app.Config().Redacted())
		return
	}
	var cfg config.ClientConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, 400, err)
		return
	}
	// Never accept secrets over the redacted echo: empty secret fields keep
	// their stored values.
	cur := b.app.Config()
	if cfg.Dero.RPCPassword == "" || cfg.Dero.RPCPassword == "***" {
		cfg.Dero.RPCPassword = cur.Dero.RPCPassword
	}
	if cfg.Wallet.Password == "" || cfg.Wallet.Password == "***" {
		cfg.Wallet.Password = cur.Wallet.Password
	}
	if err := b.app.UpdateConfig(cfg, ""); err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, b.app.Config().Redacted())
}

func (b *Backend) handleCircuit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EntryID  string `json:"entry_id"`
		MiddleID string `json:"middle_id"`
		ExitID   string `json:"exit_id"`
		Auto     bool   `json:"auto"`
		Hops     int    `json:"hops"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	var err error
	switch {
	case req.Auto || (req.EntryID == "" && req.ExitID == "" && req.MiddleID == ""):
		if req.Hops > 1 {
			if auto, ok := b.app.(interface{ AutoCircuitHops(int) error }); ok {
				err = auto.AutoCircuitHops(req.Hops)
			} else {
				err = b.app.AutoCircuit()
			}
		} else {
			err = b.app.AutoCircuit()
		}
	case req.MiddleID != "":
		if three, ok := b.app.(interface {
			BuildCircuit3(entryID, middleID, exitID string) error
		}); ok {
			err = three.BuildCircuit3(req.EntryID, req.MiddleID, req.ExitID)
		} else {
			err = b.app.BuildCircuit(req.EntryID, req.ExitID)
		}
	default:
		err = b.app.BuildCircuit(req.EntryID, req.ExitID)
	}
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, b.app.State())
}

// handleGuard resets the sticky entry guard (manual user action): the
// next rotation or rebuild may select a fresh entry. Read-only GET
// reports guard state from the current circuit snapshot.
func (b *Backend) handleGuard(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, b.app.State().Circuit)
		return
	}
	if reset, ok := b.app.(interface{ ResetGuard() }); ok {
		reset.ResetGuard()
	}
	writeJSON(w, b.app.State().Circuit)
}

func (b *Backend) handleRotate(w http.ResponseWriter, r *http.Request) {
	if err := b.app.RotateCircuit(); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, b.app.State())
}

func (b *Backend) handleApprove(w http.ResponseWriter, r *http.Request) {
	b.app.RequestPaymentApproval()
	writeJSON(w, b.app.Payment())
}

func (b *Backend) handleConfirm(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Amount float64 `json:"amount_dero"`
		TxID   string  `json:"txid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, err)
		return
	}
	if err := b.app.ConfirmPayment(req.Amount, req.TxID); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, b.app.Payment())
}
