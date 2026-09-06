// Command veilnet-service is the privileged daemon. It hosts the tunnel
// engine, firewall, and DNS so the GUI never needs admin rights. Clients
// (veilnet GUI/CLI) reach it over IPC with the token in
// ~/.veilnet/service.token.
//
// Engine wiring: the real WireGuard engine (internal/tunnel) is injected
// via newEngine (see engine_adapter.go). Leak protection is injected via
// newEnforcer (see enforce.go): the service applies the kill switch, DNS
// mode and IPv6 posture on Connect and restores them on Disconnect. A
// connection whose protection cannot be applied is torn down rather than
// reported as PROTECTED.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/dero-veilnet/veilnet/internal/app"
	"github.com/dero-veilnet/veilnet/internal/config"
	"github.com/dero-veilnet/veilnet/internal/ipc"
	"github.com/dero-veilnet/veilnet/internal/storage"
)

func main() {
	tcp := flag.String("tcp", "", "also listen on TCP addr (default "+ipc.DefaultTCPAddr+" off Windows, on)")
	flag.Parse()

	token, err := ipc.LoadOrCreateToken("")
	if err != nil {
		fatal(err)
	}
	cfg, err := config.LoadClient("")
	if err != nil {
		fatal(err)
	}
	store, err := storage.Open("")
	if err != nil {
		fatal(err)
	}
	defer store.Close()

	engine, eerr := newEngine(cfg)
	if eerr != nil {
		fatal(fmt.Errorf("tunnel engine: %w", eerr))
	}
	a := app.New(cfg, store, engine, app.NewStaticNodes(nil))
	a.SetEnforcer(newEnforcer())
	// A crashed previous run can leave rules behind; clear them before
	// serving so the box is never left half-blocked.
	if err := a.ClearEnforcement(); err != nil {
		fmt.Fprintln(os.Stderr, "veilnet-service: stale enforcement cleanup:", err)
	}

	srv := ipc.NewServer(token, func(op string, payload json.RawMessage) (any, error) {
		return dispatch(a, op, payload)
	})

	if isWindows() {
		ln, err := listenPipe()
		if err != nil {
			fatal(fmt.Errorf("listen pipe: %w", err))
		}
		go srv.Serve(ln)
		fmt.Println("veilnet-service: named pipe ready")
	}
	tcpAddr := *tcp
	if tcpAddr == "" && !isWindows() {
		tcpAddr = ipc.DefaultTCPAddr
	}
	if tcpAddr != "" {
		ln, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			fatal(fmt.Errorf("listen tcp: %w", err))
		}
		go srv.Serve(ln)
		fmt.Println("veilnet-service: tcp ready on", tcpAddr)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	srv.Close()
}

func dispatch(a *app.App, op string, payload json.RawMessage) (any, error) {
	switch op {
	case ipc.OpStatus:
		return a.State(), nil
	case ipc.OpListNodes:
		return a.ListNodes()
	case ipc.OpConnect:
		var req struct {
			NodeID string `json:"node_id"`
		}
		if len(payload) > 0 {
			if err := json.Unmarshal(payload, &req); err != nil {
				return nil, err
			}
		}
		if err := a.Connect(req.NodeID); err != nil {
			return nil, err
		}
		return a.State(), nil
	case ipc.OpDisconnect:
		if err := a.Disconnect(); err != nil {
			return nil, err
		}
		return a.State(), nil
	case ipc.OpDiagnostics:
		return a.Diagnose(), nil
	case ipc.OpPayment:
		return a.Payment(), nil
	case ipc.OpGetConfig:
		return a.Config().Redacted(), nil
	case ipc.OpSetConfig:
		var cfg config.ClientConfig
		if err := json.Unmarshal(payload, &cfg); err != nil {
			return nil, err
		}
		cur := a.Config()
		if cfg.Dero.RPCPassword == "" || cfg.Dero.RPCPassword == "***" {
			cfg.Dero.RPCPassword = cur.Dero.RPCPassword
		}
		if cfg.Wallet.Password == "" || cfg.Wallet.Password == "***" {
			cfg.Wallet.Password = cur.Wallet.Password
		}
		if err := a.UpdateConfig(cfg, ""); err != nil {
			return nil, err
		}
		return a.Config().Redacted(), nil
	case ipc.OpCircuit:
		var req struct {
			EntryID string `json:"entry_id"`
			ExitID  string `json:"exit_id"`
			Auto    bool   `json:"auto"`
		}
		if len(payload) > 0 {
			if err := json.Unmarshal(payload, &req); err != nil {
				return nil, err
			}
		}
		if req.Auto || (req.EntryID == "" && req.ExitID == "") {
			if err := a.AutoCircuit(); err != nil {
				return nil, err
			}
		} else if err := a.BuildCircuit(req.EntryID, req.ExitID); err != nil {
			return nil, err
		}
		return a.State(), nil
	case ipc.OpRotate:
		if err := a.RotateCircuit(); err != nil {
			return nil, err
		}
		return a.State(), nil
	case ipc.OpApprovePayment:
		a.RequestPaymentApproval()
		return a.Payment(), nil
	case ipc.OpConfirmPayment:
		var req struct {
			Amount float64 `json:"amount_dero"`
			TxID   string  `json:"txid"`
		}
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, err
		}
		if err := a.ConfirmPayment(req.Amount, req.TxID); err != nil {
			return nil, err
		}
		return a.Payment(), nil
	case ipc.OpWalletStatus:
		var req struct {
			Refresh bool `json:"refresh"`
		}
		if len(payload) > 0 {
			_ = json.Unmarshal(payload, &req)
		}
		if req.Refresh {
			return a.RefreshWallet(), nil
		}
		return a.WalletStatus(), nil
	case ipc.OpWalletConnect:
		var spec app.WalletConnectSpec
		if err := json.Unmarshal(payload, &spec); err != nil {
			return nil, err
		}
		return a.ConnectWallet(spec)
	case ipc.OpWalletDisconnect:
		if err := a.DisconnectWallet(); err != nil {
			return nil, err
		}
		return a.WalletStatus(), nil
	case ipc.OpWalletPay:
		var req struct {
			Destination string  `json:"destination"`
			AmountDero  float64 `json:"amount_dero"`
		}
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, err
		}
		txid, err := a.PayApproved(req.Destination, req.AmountDero)
		if err != nil {
			return nil, err
		}
		return map[string]any{"txid": txid, "payment": a.Payment()}, nil
	default:
		return nil, fmt.Errorf("unknown op %q", op)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "veilnet-service:", err)
	os.Exit(1)
}
