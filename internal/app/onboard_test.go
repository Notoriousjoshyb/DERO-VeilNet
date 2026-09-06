package app

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/dero-veilnet/veilnet/internal/config"
	"github.com/dero-veilnet/veilnet/internal/storage"
)

// TestOnboardingJourney proves the zero-config first run end to end:
// missing config -> defaults auto-created on disk; wallet-free connect to a
// demo node; explicit-approval flagging for paid nodes; receipts, settings,
// and connection history surviving a restart; unclean-exit detection.
func TestOnboardingJourney(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".veilnet", "config.toml")
	dbPath := filepath.Join(dir, ".veilnet", "client.db")

	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// First run: no config file -> defaults + auto-created file.
	rep, cfg, err := EnsureFirstRun(cfgPath, store)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.IsFirstRun || !rep.ConfigCreated {
		t.Fatalf("expected first run with created config, got %+v", rep)
	}
	if cfg.Network.SelectPolicy != config.SelectFastest {
		t.Fatalf("default policy = %q, want FASTEST", cfg.Network.SelectPolicy)
	}
	if cfg.DNS.Mode != config.DNSVeilnet {
		t.Fatalf("default DNS = %q, want VEILNET", cfg.DNS.Mode)
	}
	if cfg.KillSwitch != config.KillWhileConnected {
		t.Fatalf("default killswitch = %q, want ON_WHILE_CONNECTED", cfg.KillSwitch)
	}
	if cfg.Dero.Network != "mainnet" {
		t.Fatalf("default network = %q, want explicit mainnet", cfg.Dero.Network)
	}
	if rep.WalletNote == "" {
		t.Fatal("expected wallet-optional note when no wallet is configured")
	}
	if ServiceInstallHint() == "" {
		t.Fatal("service install hint must name the fix, never be empty")
	}

	// Second bootstrap on the same store sees no first run but a dirty
	// sentinel (no clean shutdown happened yet) -> reconnect prompt case.
	rep2, _, err := EnsureFirstRun(cfgPath, store)
	if err != nil {
		t.Fatal(err)
	}
	if rep2.IsFirstRun || rep2.ConfigCreated {
		t.Fatalf("second run must not be first run, got %+v", rep2)
	}
	if !rep2.UncleanExit {
		t.Fatal("expected unclean-exit flag while the dirty sentinel is set")
	}

	// App journey: fastest auto-connect, paid-node approval flag, receipt,
	// settings change, then clean shutdown.
	a := New(cfg, store, NewFakeEngine(), NewStaticNodes(append([]NodeInfo(nil), demoNodes...)))
	needsApproval, node, err := a.NeedsPaymentApproval("")
	if err != nil {
		t.Fatal(err)
	}
	if !needsApproval {
		t.Fatal("demo nodes are paid fixtures; approval dialog must trigger")
	}
	if p := PaymentApprovalPrompt(node); p == "" {
		t.Fatal("approval prompt must carry real node values")
	}
	if err := a.Connect(node.NodeID); err != nil {
		t.Fatal(err)
	}
	// FakeEngine handshakes async (CONNECTING -> UP); wait for real UP state.
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := a.State()
		if st.EngineState == StateUp {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("engine = %q, want UP before receipts persist", st.EngineState)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := a.ConfirmPayment(0.05, "journey-tx-1"); err != nil {
		t.Fatal(err)
	}
	cfg.Region = "eu-west"
	if err := a.UpdateConfig(cfg, cfgPath); err != nil {
		t.Fatal(err)
	}
	if err := a.Disconnect(); err != nil {
		t.Fatal(err)
	}
	if err := MarkCleanShutdown(store); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()

	// Restart: everything survives.
	store2, err := storage.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	rep3, cfg3, err := EnsureFirstRun(cfgPath, store2)
	if err != nil {
		t.Fatal(err)
	}
	if rep3.UncleanExit {
		t.Fatal("clean shutdown must clear the unclean-exit flag")
	}
	if cfg3.Region != "eu-west" {
		t.Fatalf("region = %q, want persisted eu-west", cfg3.Region)
	}
	receipts, err := store2.ListReceipts(100)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 || receipts[0].TxID != "journey-tx-1" {
		t.Fatalf("receipts did not survive restart: %+v", receipts)
	}
	conns, err := store2.ListConnections(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) == 0 || conns[0].NodeID != node.NodeID {
		t.Fatalf("connection history did not survive restart: %+v", conns)
	}
	// The restart bootstrap re-arms the dirty sentinel for this run; the
	// clean-shutdown proof is rep3.UncleanExit == false above.
	if got, _ := store2.GetSetting(cleanExitSetting); got != "0" {
		t.Fatalf("clean_exit = %q, want 0 (sentinel re-armed by restart bootstrap)", got)
	}
}

// TestClassifyConnectError checks every catalog code maps to a cause and a
// fix, and unknown errors still get an actionable fix.
func TestClassifyConnectError(t *testing.T) {
	cases := map[string]string{
		"service unreachable (start veilnet-service)": ErrCodeServiceDown,
		"no tunnel engine wired":                      ErrCodeServiceDown,
		`open C:\Users\veil\.veilnet\service.token: file not found`: ErrCodeServiceDown,
		"no suitable nodes available":                 ErrCodeNoNodes,
		`node "x" not found`:                          ErrCodeNoNodes,
		"session token rejected":                      ErrCodeAuthRejected,
		"payment declined":                            ErrCodePaymentDeclined,
		"dns blocked while connected":                 ErrCodeDNSBlocked,
		"wireguard handshake timeout":                 ErrCodeTunnelFailed,
		"something completely new":                    ErrCodeConnectFailed,
	}
	for msg, want := range cases {
		t.Run(want+"/"+msg, func(t *testing.T) {
			oe := ClassifyConnectError(errString(msg))
			if oe.Code != want {
				t.Fatalf("code = %q, want %q", oe.Code, want)
			}
			if oe.Cause == "" || oe.Fix == "" {
				t.Fatalf("cause+fix must never be empty: %+v", oe)
			}
		})
	}
	if ClassifyConnectError(nil) != nil {
		t.Fatal("nil error must map to nil")
	}
}

// TestUnpaidNodeNeedsNoApproval proves the wallet-optional path: price-0 dev
// nodes connect without the approval dialog.
func TestUnpaidNodeNeedsNoApproval(t *testing.T) {
	store, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	free := NodeInfo{NodeID: "dev-free-01", Status: "active", PricePerHourDero: 0, Endpoint: "127.0.0.1:51829"}
	a := New(config.DefaultClientConfig(), store, NewFakeEngine(), NewStaticNodes([]NodeInfo{free}))
	needs, _, err := a.NeedsPaymentApproval(free.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if needs {
		t.Fatal("unpaid dev node must not require approval")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
