// Command veilnet is the client: GUI (loopback HTTP + embedded frontend,
// Wails-bindable backend) plus CLI flags.
//
//	veilnet --demo                  demo GUI (badged, isolated from prod)
//	veilnet --demo --connect [id]   connect demo node, live timer/stats
//	veilnet --demo --status         print demo state JSON
//	veilnet --status                print service state JSON
//	veilnet --connect [id]          connect via the privileged service
//
// Prod traffic control stays in veilnet-service; the GUI never needs admin.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"github.com/dero-veilnet/veilnet/internal/app"
	"github.com/dero-veilnet/veilnet/internal/config"
	"github.com/dero-veilnet/veilnet/internal/ipc"
	"github.com/dero-veilnet/veilnet/internal/storage"
	"github.com/dero-veilnet/veilnet/internal/ui"
)

func main() {
	// Allow bare `--connect` (auto-select) alongside `--connect ID`.
	// Only rewrite when no value follows; otherwise the flag package
	// consumes the next arg as the node id.
	for i, a := range os.Args {
		if a == "--connect" && (i+1 >= len(os.Args) || strings.HasPrefix(os.Args[i+1], "-")) {
			os.Args[i] = "--connect=__auto__"
		}
	}
	demo := flag.Bool("demo", false, "run with seeded fake nodes, isolated from prod")
	connectFlag := flag.String("connect", "", "connect to node id, or auto-select when empty; CLI mode")
	status := flag.Bool("status", false, "print state JSON and exit")
	disc := flag.Bool("disconnect", false, "disconnect and exit")
	setup := flag.Bool("setup", false, "print environment report with fix hints and exit")
	listen := flag.String("listen", "127.0.0.1:18280", "loopback address for the GUI")
	noBrowser := flag.Bool("no-browser", false, "do not open a browser window")
	flag.Parse()

	if *setup {
		runSetup()
		return
	}

	connID, wantConn := "", false
	if *connectFlag != "" {
		wantConn = true
		if *connectFlag != "__auto__" {
			connID = *connectFlag
		}
	}

	if *demo {
		runDemo(*status, *disc, connID, wantConn, *listen, *noBrowser)
		return
	}
	runProd(*status, *disc, connID, wantConn, *listen, *noBrowser)
}

// ---- demo ----

func runDemo(status, disc bool, connID string, wantConn bool, listen string, noBrowser bool) {
	a, err := app.NewDemo()
	if err != nil {
		fatal(err)
	}
	defer a.Close()
	// Zero-config first run: auto-create the default config file so a fresh
	// HOME connects with no manual edits.
	if rep, rerr := a.EnsureFirstRun(""); rerr != nil {
		fatal(rerr)
	} else {
		firstRunNotice(rep)
	}
	switch {
	case status:
		dump(a.State())
	case disc:
		fmt.Println(`{"ok":false,"error":"demo is not connected"}`)
	case wantConn:
		if connID == "" {
			nodes, err := a.ListNodes()
			if err != nil || len(nodes) == 0 {
				fatal(app.ClassifyConnectError(fmt.Errorf("no demo nodes")))
			}
			connID = nodes[0].NodeID
		}
		if needs, node, nerr := a.NeedsPaymentApproval(connID); nerr != nil {
			fatal(nerr)
		} else if needs {
			fmt.Fprintln(os.Stderr, "approval: "+app.PaymentApprovalPrompt(node))
		}
		if err := a.Connect(connID); err != nil {
			fatal(app.ClassifyConnectError(err))
		}
		liveLoop(a)
	default:
		serveUI(a, listen, noBrowser)
	}
}

// ---- prod ----

func runProd(status, disc bool, connID string, wantConn bool, listen string, noBrowser bool) {
	store, err := storage.Open("")
	if err != nil {
		fatal(err)
	}
	defer store.Close()
	// Zero-config first run: missing file -> safe defaults auto-created.
	rep, cfg, ferr := app.EnsureFirstRun("", store)
	if ferr != nil {
		fatal(ferr)
	}
	firstRunNotice(rep)
	defer func() { _ = app.MarkCleanShutdown(store) }()

	if status || disc || wantConn {
		// Headless ops go through the privileged service.
		c, err := dialService()
		if err != nil {
			fatal(app.ClassifyConnectError(err))
		}
		var st app.ConnState
		switch {
		case status:
			if err := c.Call(ipc.OpStatus, nil, &st); err != nil {
				fatal(app.ClassifyConnectError(err))
			}
		case disc:
			if err := c.Call(ipc.OpDisconnect, nil, &st); err != nil {
				fatal(app.ClassifyConnectError(err))
			}
			_ = app.MarkCleanShutdown(store)
		default:
			if err := c.Call(ipc.OpConnect, map[string]string{"node_id": connID}, &st); err != nil {
				fatal(app.ClassifyConnectError(err))
			}
			paidNotice(st)
		}
		dump(st)
		return
	}

	// GUI: prefer the service when reachable (it owns the engine), else a
	// local view-only app (connect explains that the service is required).
	if c, err := dialService(); err == nil {
		var probe app.ConnState
		if cerr := c.Call(ipc.OpStatus, nil, &probe); cerr == nil {
			serveUI(newRemoteApp(c), listen, noBrowser)
			return
		}
	}
	serveUI(app.New(cfg, store, nil, app.NewStaticNodes(nil)), listen, noBrowser)
}

// ---- UI server ----

func serveUI(p ui.Provider, listen string, noBrowser bool) {
	srv := &http.Server{Handler: ui.NewBackend(p).Handler()}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("VeilNet UI on http://%s\n", ln.Addr())
	if !noBrowser {
		openBrowser("http://" + ln.Addr().String())
	}
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		fatal(err)
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

// ---- live timer/stats loop ----

func liveLoop(a *app.App) {
	fmt.Println("Connected. Live stats (Ctrl-C to stop):")
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for range tick.C {
		st := a.State()
		node := "-"
		if st.Node != nil {
			node = st.Node.NodeID
		}
		fmt.Printf("state=%s node=%s elapsed=%ds rx=%d tx=%d\n",
			st.EngineState, node, st.ElapsedSecs, st.RxBytes, st.TxBytes)
	}
}

// ---- remote provider over IPC ----

type remoteApp struct {
	c *ipc.Client
}

func newRemoteApp(c *ipc.Client) *remoteApp { return &remoteApp{c: c} }

func (r *remoteApp) State() app.ConnState {
	var st app.ConnState
	_ = r.c.Call(ipc.OpStatus, nil, &st)
	return st
}

func (r *remoteApp) ListNodes() ([]app.NodeInfo, error) {
	var out []app.NodeInfo
	err := r.c.Call(ipc.OpListNodes, nil, &out)
	return out, err
}

func (r *remoteApp) Connect(nodeID string) error {
	var st app.ConnState
	return r.c.Call(ipc.OpConnect, map[string]string{"node_id": nodeID}, &st)
}

func (r *remoteApp) Disconnect() error {
	return r.c.Call(ipc.OpDisconnect, nil, nil)
}

func (r *remoteApp) Diagnose() app.Diagnostics {
	var d app.Diagnostics
	_ = r.c.Call(ipc.OpDiagnostics, nil, &d)
	return d
}

func (r *remoteApp) Payment() app.PaymentInfo {
	var p app.PaymentInfo
	_ = r.c.Call(ipc.OpPayment, nil, &p)
	return p
}

func (r *remoteApp) Config() config.ClientConfig {
	var cfg config.ClientConfig
	_ = r.c.Call(ipc.OpGetConfig, nil, &cfg)
	return cfg
}

func (r *remoteApp) UpdateConfig(cfg config.ClientConfig, _ string) error {
	var out config.ClientConfig
	return r.c.Call(ipc.OpSetConfig, cfg, &out)
}

func (r *remoteApp) BuildCircuit(entryID, exitID string) error {
	return r.c.Call(ipc.OpCircuit, map[string]string{"entry_id": entryID, "exit_id": exitID}, nil)
}

func (r *remoteApp) AutoCircuit() error {
	return r.c.Call(ipc.OpCircuit, map[string]bool{"auto": true}, nil)
}

func (r *remoteApp) RotateCircuit() error { return r.c.Call(ipc.OpRotate, nil, nil) }

func (r *remoteApp) RequestPaymentApproval() {
	_ = r.c.Call(ipc.OpApprovePayment, nil, nil)
}

func (r *remoteApp) ConfirmPayment(amount float64, txid string) error {
	return r.c.Call(ipc.OpConfirmPayment, map[string]any{"amount_dero": amount, "txid": txid}, nil)
}

// ---- wallet (RPC / XSWD) over IPC ----
//
// The service owns the wallet connection so a single session is shared
// by the GUI and the CLI. Passwords travel over the authenticated local
// pipe only and are never echoed back.

func (r *remoteApp) WalletStatus() app.WalletStatus {
	var st app.WalletStatus
	_ = r.c.Call(ipc.OpWalletStatus, nil, &st)
	return st
}

func (r *remoteApp) RefreshWallet() app.WalletStatus {
	var st app.WalletStatus
	_ = r.c.Call(ipc.OpWalletStatus, map[string]bool{"refresh": true}, &st)
	return st
}

func (r *remoteApp) ConnectWallet(spec app.WalletConnectSpec) (app.WalletStatus, error) {
	var st app.WalletStatus
	err := r.c.Call(ipc.OpWalletConnect, spec, &st)
	return st, err
}

func (r *remoteApp) DisconnectWallet() error {
	return r.c.Call(ipc.OpWalletDisconnect, nil, nil)
}

func (r *remoteApp) PayApproved(dest string, amountDero float64) (string, error) {
	var out struct {
		TXID string `json:"txid"`
	}
	err := r.c.Call(ipc.OpWalletPay,
		map[string]any{"destination": dest, "amount_dero": amountDero}, &out)
	return out.TXID, err
}

// ---- helpers ----

func dialService() (*ipc.Client, error) {
	tok, err := ipc.LoadToken("")
	if err != nil {
		return nil, err
	}
	return ipc.NewClient(tok), nil
}

func demoConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".veilnet", "demo-config.toml")
}

func dump(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "veilnet:", err)
	os.Exit(1)
}
