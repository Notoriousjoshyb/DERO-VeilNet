// Package app onboarding: zero-config first run, user-facing error catalog,
// wallet-optional path, and crash-safe restart state.
//
// First run with no config file works: EnsureFirstRun loads defaults
// (FASTEST policy, VEILNET DNS, ON_WHILE_CONNECTED killswitch, mainnet) and
// auto-creates the config file so nothing needs manual editing. Paid nodes
// never spend silently: NeedsPaymentApproval reports whether a node requires
// the explicit approval dialog. Every connect-time failure maps to an
// OnboardError (cause + fix) via ClassifyConnectError for UI and CLI stderr.
package app

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/dero-veilnet/veilnet/internal/config"
	"github.com/dero-veilnet/veilnet/internal/platform"
	"github.com/dero-veilnet/veilnet/internal/storage"
)

// User-facing error codes. Stable strings shared with the GUI wizard.
const (
	ErrCodeServiceDown     = "service-down"
	ErrCodeNoNodes         = "no-nodes"
	ErrCodeAuthRejected    = "auth-rejected"
	ErrCodePaymentDeclined = "payment-declined"
	ErrCodeTunnelFailed    = "tunnel-failed"
	ErrCodeDNSBlocked      = "dns-blocked"
	ErrCodeConnectFailed   = "connect-failed"
)

// cleanExitSetting persists across restarts: "1" after a clean shutdown,
// "0" while running. A "0" at startup means the last exit was unclean.
const cleanExitSetting = "veilnet.clean_exit"

// OnboardError is a user-facing error: what happened and how to fix it.
// It wraps the underlying error for logs; display Code/Cause/Fix to users.
type OnboardError struct {
	Code  string
	Cause string
	Fix   string
	Err   error
}

func (e *OnboardError) Error() string {
	s := "veilnet [" + e.Code + "]: " + e.Cause + " Fix: " + e.Fix
	if e.Err != nil {
		s += " (" + e.Err.Error() + ")"
	}
	return s
}

// Unwrap exposes the underlying error.
func (e *OnboardError) Unwrap() error { return e.Err }

// ServiceInstallHint names the exact per-OS command that installs/starts the
// privileged service, delegated to the platform contract so shared logic
// carries no OS branches.
func ServiceInstallHint() string { return platform.DefaultService().InstallHint() }

// ClassifyConnectError maps any connect-time failure to cause + fix.
// Unknown errors keep their text and get the generic diagnostics fix;
// nothing is ever returned without an actionable fix.
func ClassifyConnectError(err error) *OnboardError {
	if err == nil {
		return nil
	}
	var oe *OnboardError
	if errors.As(err, &oe) {
		return oe
	}
	msg := strings.ToLower(err.Error())
	switch {
	case containsAny(msg, []string{"service unreachable", "no tunnel engine", "service not", "service.token", "no such file", "cannot find the file", "pipe", "connection refused"}):
		return &OnboardError{
			Code:  ErrCodeServiceDown,
			Cause: "the privileged service is not reachable, so no tunnel can be built",
			Fix:   "start the service: " + ServiceInstallHint(),
			Err:   err,
		}
	case containsAny(msg, []string{"no suitable nodes", "no demo nodes", "not found", "no nodes"}):
		return &OnboardError{
			Code:  ErrCodeNoNodes,
			Cause: "no usable exit nodes answered discovery",
			Fix:   "try --demo for local nodes, pick another region, or check the registry/devnet is up",
			Err:   err,
		}
	case containsAny(msg, []string{"auth", "token", "unauthorized", "rejected", "forbidden", "revoked"}):
		return &OnboardError{
			Code:  ErrCodeAuthRejected,
			Cause: "the node rejected the session authorization",
			Fix:   "disconnect, restart the service to refresh credentials, then reconnect",
			Err:   err,
		}
	case containsAny(msg, []string{"payment", "approv", "declin", "insufficient", "spend", "balance"}):
		return &OnboardError{
			Code:  ErrCodePaymentDeclined,
			Cause: "payment was declined or still needs your explicit approval; nothing was spent",
			Fix:   "open the Payment screen, review the amount, and approve explicitly; check wallet RPC and DERO balance",
			Err:   err,
		}
	case containsAny(msg, []string{"dns"}):
		return &OnboardError{
			Code:  ErrCodeDNSBlocked,
			Cause: "name resolution is blocked by the DNS posture",
			Fix:   "set DNS mode to VEILNET in Settings and re-check Diagnostics",
			Err:   err,
		}
	case containsAny(msg, []string{"tunnel", "wireguard", "handshake", "peer", "endpoint", "timeout", "network", "unreachable"}):
		return &OnboardError{
			Code:  ErrCodeTunnelFailed,
			Cause: "the encrypted tunnel to the node could not be established",
			Fix:   "retry, auto-select the fastest node, or check your firewall allows UDP",
			Err:   err,
		}
	default:
		return &OnboardError{
			Code:  ErrCodeConnectFailed,
			Cause: "connection failed",
			Fix:   "open Diagnostics, then run veilnet --setup for a fix hint",
			Err:   err,
		}
	}
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// FirstRunReport describes what EnsureFirstRun found and did.
type FirstRunReport struct {
	// IsFirstRun is true when no config file existed (defaults were written).
	IsFirstRun bool
	// ConfigCreated is true when the config file was auto-created this run.
	ConfigCreated bool
	// ConfigPath is the resolved client config path.
	ConfigPath string
	// UncleanExit is true when the previous run did not shut down cleanly.
	UncleanExit bool
	// KillswitchSentinel is true when ALWAYS_ON is configured, meaning the
	// kill switch posture must be respected even while disconnected.
	KillswitchSentinel bool
	// WalletNote explains the wallet-optional path when no wallet is set.
	WalletNote string
}

// EnsureFirstRun implements the zero-config first run against store:
// missing config file yields safe defaults which are then auto-created on
// disk; devnet stays off unless explicitly chosen (defaults are mainnet;
// only --demo or an explicit config edit leaves it); the shutdown sentinel
// is marked dirty so the next start can offer a reconnect prompt. The
// returned config is what the caller must use.
func EnsureFirstRun(cfgPath string, store *storage.Store) (FirstRunReport, config.ClientConfig, error) {
	var rep FirstRunReport
	cfg, err := config.LoadClient(cfgPath)
	if err != nil {
		return rep, cfg, ClassifyConnectError(fmt.Errorf("config invalid: %w", err))
	}
	if cfgPath == "" {
		p, err := config.ClientConfigPath()
		if err != nil {
			return rep, cfg, err
		}
		cfgPath = p
	}
	rep.ConfigPath = cfgPath
	if _, serr := os.Stat(cfgPath); errors.Is(serr, os.ErrNotExist) {
		rep.IsFirstRun = true
		// Explicit mainnet: defaults never point at a devnet; --demo or an
		// explicit config edit is the only way off mainnet.
		if cfg.Dero.Network == "" {
			cfg.Dero.Network = "mainnet"
		}
		if err := cfg.Save(cfgPath); err != nil {
			return rep, cfg, fmt.Errorf("create default config at %s: %w", cfgPath, err)
		}
		rep.ConfigCreated = true
	}
	if store != nil {
		if prev, gerr := store.GetSetting(cleanExitSetting); gerr == nil && prev == "0" {
			rep.UncleanExit = true
		}
		// Mark dirty; MarkCleanShutdown flips it back on clean exit.
		_ = store.SetSetting(cleanExitSetting, "0")
	}
	rep.KillswitchSentinel = cfg.KillSwitch == config.KillAlwaysOn
	if !walletConfigured(cfg) {
		rep.WalletNote = "no wallet configured: demo and unpaid dev nodes work without one; " +
			"paid nodes show an explicit approval dialog before anything is spent"
	}
	return rep, cfg, nil
}

// EnsureFirstRun bootstraps zero-config first run using the app's store,
// swaps the loaded (or defaulted) config into the app, and reports status.
func (a *App) EnsureFirstRun(cfgPath string) (FirstRunReport, error) {
	rep, cfg, err := EnsureFirstRun(cfgPath, a.store)
	if err != nil {
		return rep, err
	}
	a.mu.Lock()
	a.cfg = cfg
	a.mu.Unlock()
	return rep, nil
}

// MarkCleanShutdown records a clean exit so the next start offers no
// reconnect prompt. Call on disconnect paths and shutdown.
func MarkCleanShutdown(store *storage.Store) error {
	if store == nil {
		return nil
	}
	return store.SetSetting(cleanExitSetting, "1")
}

// NeedsPaymentApproval reports whether connecting to nodeID requires the
// explicit payment approval dialog. Demo and unpaid (price 0) dev nodes
// work wallet-free; paid nodes always need explicit approval and VeilNet
// never auto-spends.
func (a *App) NeedsPaymentApproval(nodeID string) (needsApproval bool, node NodeInfo, err error) {
	if nodeID == "" {
		node, err = a.AutoSelect()
	} else {
		node, err = a.findNode(nodeID)
	}
	if err != nil {
		return false, NodeInfo{}, ClassifyConnectError(err)
	}
	return node.PricePerHourDero > 0, node, nil
}

// PaymentApprovalPrompt is the exact dialog text the GUI/CLI shows before a
// paid connection. Amount and node name are real values from discovery.
func PaymentApprovalPrompt(node NodeInfo) string {
	return fmt.Sprintf("Node %s costs %.4f DERO/hour. Approve explicitly to continue; VeilNet never spends without approval.",
		node.NodeID, node.PricePerHourDero)
}

func walletConfigured(cfg config.ClientConfig) bool {
	return cfg.Wallet.Name != "" || cfg.Wallet.Password != ""
}
