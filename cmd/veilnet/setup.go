// Command veilnet first-run setup report.
//
// veilnet --setup prints an environment report (OS, admin, config, service
// state, dependencies, DERO reachability) where every failure names its fix.
// It never edits config; it only reports. Exit code is always 0.
package main

import (
	"bytes"
	"context"
	"fmt"
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
	"github.com/dero-veilnet/veilnet/internal/transport"
)

// runSetup prints the actionable environment report to stdout.
func runSetup() {
	fmt.Println("VeilNet setup report")
	fmt.Println("--------------------")
	issues := 0
	report := func(ok bool, format string, args ...any) {
		mark := "ok"
		if !ok {
			mark = "FIX"
			issues++
		}
		fmt.Printf("[%s] %s\n", mark, fmt.Sprintf(format, args...))
	}

	report(true, "OS: %s/%s", runtime.GOOS, runtime.GOARCH)

	admin, how := isAdmin()
	if admin {
		report(true, "admin: yes (%s)", how)
	} else {
		report(false, "admin: no (%s) -- service install needs elevation, the GUI itself never does", how)
	}

	cfgPath, perr := config.ClientConfigPath()
	if perr != nil {
		report(false, "config path: %v -- set HOME so ~/.veilnet is writable", perr)
		cfgPath = ""
	}
	cfg, cerr := config.LoadClient("")
	if cerr != nil {
		report(false, "config %s: invalid (%v) -- fix the named field or delete the file for fresh defaults", cfgPath, cerr)
	} else if cfgPath != "" {
		if _, serr := os.Stat(cfgPath); serr != nil {
			report(true, "config: no file yet -- first run auto-creates %s with safe defaults", cfgPath)
		} else {
			report(true, "config: %s valid (policy=%s dns=%s killswitch=%s network=%s)",
				cfgPath, cfg.Network.SelectPolicy, cfg.DNS.Mode, cfg.KillSwitch, cfg.Dero.Network)
		}
	}
	if cerr == nil && cfg.Dero.Network != "mainnet" && cfg.Dero.Network != "" {
		report(false, "dero network=%q -- devnet/testnet is explicit-only; switch back unless testing", cfg.Dero.Network)
	}

	if cerr == nil {
		// A missing bridge transport must be loud: believing you are
		// bridged while sending plain UDP is worse than not starting.
		tr, terr := transport.Get(cfg.Network.Transport)
		switch {
		case terr != nil:
			report(false, "transport: %v", terr)
		case tr.Obfuscating():
			report(true, "transport: %s -- %s", tr.Name(), tr.Description())
		default:
			report(true, "transport: %s -- %s (no censorship resistance claimed)",
				tr.Name(), tr.Description())
		}

		switch cfg.Cover.Mode {
		case "", config.CoverOff:
			report(true, "cover traffic: OFF -- sizes and timing are not disguised (default)")
		case config.CoverPad:
			report(true, "cover traffic: PAD -- packet sizes bucketed; timing is NOT hidden")
		case config.CoverConstant:
			report(true, "cover traffic: CONSTANT %dB every %dms (max overhead %.0f%%) -- size and timing hidden while the link keeps up",
				cfg.Cover.CellSizeBytes, cfg.Cover.IntervalMs, cfg.Cover.MaxOverhead*100)
		default:
			report(false, "cover traffic: unknown mode %q -- use OFF, PAD or CONSTANT", cfg.Cover.Mode)
		}
	}

	tokPath, terr := ipc.TokenPath()
	if terr != nil {
		report(false, "service token: %v -- start the service once to mint it", terr)
	} else if _, serr := os.Stat(tokPath); serr != nil {
		report(false, "service token: missing at %s -- %s", tokPath, app.ServiceInstallHint())
	} else {
		report(true, "service token: present at %s", tokPath)
	}

	if c, derr := dialService(); derr != nil {
		oe := app.ClassifyConnectError(derr)
		report(false, "service: unreachable -- %s", oe.Fix)
	} else {
		var st app.ConnState
		if cerr := c.Call(ipc.OpStatus, nil, &st); cerr != nil {
			report(false, "service: token rejected (%v) -- restart the service to refresh credentials, then retry", cerr)
		} else {
			report(true, "service: reachable (engine=%s)", st.EngineState)
		}
	}
	reportTunBackend(report)
	fmt.Println()

	dbPath, dberr := storage.ClientDBPath()
	if dberr != nil {
		report(false, "state db: %v -- set HOME so ~/.veilnet is writable", dberr)
	} else if _, serr := os.Stat(dbPath); serr != nil {
		report(true, "state db: fresh -- created on first run at %s", dbPath)
	} else {
		report(true, "state db: present at %s (settings, history, receipts persist)", dbPath)
	}

	if cerr == nil {
		endpoint := cfg.Dero.RPCEndpoint
		client := &http.Client{Timeout: 3 * time.Second}
		resp, rerr := client.Get(endpoint)
		if rerr != nil {
			report(false, "dero %s: unreachable (%v) -- start the daemon or fix dero.rpc_endpoint in %s; wallet stays optional",
				endpoint, shortErr(rerr), cfgPath)
		} else {
			_ = resp.Body.Close()
			report(true, "dero %s: reachable (http %s); control plane only, never user traffic",
				endpoint, resp.Status)
		}
		if cfg.Wallet.Name == "" && cfg.Wallet.Password == "" {
			report(true, "wallet: not configured -- demo and unpaid dev nodes work; paid nodes ask for explicit approval")
		} else {
			report(true, "wallet: configured (account set) -- payments still need explicit approval every time")
		}
	}

	fmt.Println("--------------------")
	if issues == 0 {
		fmt.Println("ready: no issues found")
	} else {
		fmt.Printf("%d issue(s) need attention (see FIX lines above)\n", issues)
	}
}

// firstRunNotice prints first-run guidance to stderr: fresh defaults,
// unclean-exit reconnect prompt, killswitch sentinel, wallet-optional note.
func firstRunNotice(rep app.FirstRunReport) {
	if rep.IsFirstRun {
		fmt.Fprintf(os.Stderr, "first run: created default config at %s (FASTEST, VEILNET DNS, killswitch ON_WHILE_CONNECTED)\n", rep.ConfigPath)
	}
	if rep.UncleanExit {
		fmt.Fprintln(os.Stderr, "notice: last run did not exit cleanly; reconnect to resume protection")
	}
	if rep.KillswitchSentinel {
		fmt.Fprintln(os.Stderr, "notice: killswitch ALWAYS_ON is configured and respected even while disconnected")
	}
	if rep.WalletNote != "" {
		fmt.Fprintln(os.Stderr, "wallet: "+rep.WalletNote)
	}
}

// paidNotice warns on stderr when the connected node is paid: explicit
// approval is required and nothing is auto-spent.
func paidNotice(st app.ConnState) {
	if st.Node != nil && st.Node.PricePerHourDero > 0 {
		fmt.Fprintln(os.Stderr, "approval: "+app.PaymentApprovalPrompt(app.NodeInfo{
			NodeID:           st.Node.NodeID,
			PricePerHourDero: st.Node.PricePerHourDero,
		}))
	}
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}

// checkPrereqs shells out to the packaging prerequisite check
// (scripts/setup.sh --check / setup.ps1 -Check) when the repo scripts are
// beside the working directory or the binary, and folds its verdict into
// the report. Missing: lines already name the per-distro fix.
func checkPrereqs(report func(bool, string, ...any)) {
	script := ""
	for _, c := range prereqScriptCandidates() {
		if _, err := os.Stat(c); err == nil {
			script = c
			break
		}
	}
	if script == "" {
		if exe, err := os.Executable(); err == nil {
			base := filepath.Dir(exe)
			for _, c := range prereqScriptCandidates() {
				if _, err := os.Stat(filepath.Join(base, c)); err == nil {
					script = filepath.Join(base, c)
					break
				}
				if _, err := os.Stat(filepath.Join(base, "..", c)); err == nil {
					script = filepath.Join(base, "..", c)
					break
				}
			}
		}
	}
	if script == "" {
		report(true, "deps: prerequisite script not found -- run %s from the repo root for the full go/git/wireguard/iptables check", prereqLabel())
		return
	}
	args := append(append([]string{}, prereqRunnerPrefix()...), script)
	args = append(args, prereqScriptArgs()...)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, prereqRunner(), args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	if out := strings.TrimSpace(buf.String()); out != "" {
		for _, line := range strings.Split(out, "\n") {
			fmt.Printf("  | %s\n", strings.TrimRight(line, "\r"))
		}
	}
	if err != nil {
		report(false, "deps: prerequisite check failed (%s) -- fix each missing: line above", prereqLabel())
	} else {
		report(true, "deps: prerequisite check passed (%s)", prereqLabel())
	}
}

// reportTunBackend names the actual TUN mechanism the tunnel engine will use.
// Windows: bundled wintun.dll beside the exe (shipped in releases) first,
// then system32, then a WireGuard install. Linux: kernel module, else
// wireguard-tools. macOS: wireguard-tools (utun). No guessing: each branch
// probes the filesystem before claiming readiness.
func reportTunBackend(report func(bool, string, ...any)) {
	switch runtime.GOOS {
	case "windows":
		cands := []string{}
		if exe, err := os.Executable(); err == nil {
			cands = append(cands, filepath.Join(filepath.Dir(exe), "wintun.dll"))
		}
		if windir := os.Getenv("SystemRoot"); windir != "" {
			cands = append(cands, filepath.Join(windir, "System32", "wintun.dll"))
		}
		for _, c := range cands {
			if _, err := os.Stat(c); err == nil {
				report(true, "tunnel: wintun driver ready at %s (userspace, no WireGuard install needed)", c)
				return
			}
		}
		if p, err := exec.LookPath("wg"); err == nil {
			report(true, "tunnel: wireguard-tools at %s (kernel/driver path available)", p)
			return
		}
		report(false, "tunnel: no wintun.dll beside veilnet.exe and no WireGuard install -- reinstall from a release zip (ships wintun.dll) or run scripts\\setup.ps1 -Install")
	case "linux":
		if _, err := os.Stat("/sys/module/wireguard"); err == nil {
			report(true, "tunnel: kernel WireGuard module present (fast path)")
			return
		}
		if p, err := exec.LookPath("wg"); err == nil {
			report(true, "tunnel: wireguard-tools at %s (kernel interface path)", p)
			return
		}
		report(true, "tunnel: embedded userspace backend (wireguard-go); install wireguard-tools for the kernel fast path")
	default: // darwin and others: utun userspace, wg optional
		if p, err := exec.LookPath("wg"); err == nil {
			report(true, "tunnel: wireguard-tools at %s; userspace utun backend ready", p)
			return
		}
		report(true, "tunnel: userspace utun backend ready (install wireguard-tools via brew for diagnostics)")
	}
}
