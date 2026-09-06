// Command veilnet-node runs the VeilNet exit/relay node daemon.
//
// Usage:
//
//	veilnet-node init-config [--config PATH] [--force]
//	veilnet-node run [--config PATH] [--dev]
//	veilnet-node status [--config PATH]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dero-veilnet/veilnet/internal/nodes"
	"github.com/dero-veilnet/veilnet/internal/session"
	"github.com/dero-veilnet/veilnet/internal/wireguard"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init-config":
		cmdInitConfig(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "rotate-keys":
		cmdRotateKeys(os.Args[2:])
	case "report-abuse":
		cmdReportAbuse(os.Args[2:])
	case "blocklist":
		cmdBlocklist(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `veilnet-node %s — VeilNet node daemon

Commands:
  init-config [--config PATH] [--force]   write default ~/.veilnet-node/config.toml
  run [--config PATH] [--dev] [--abuse-autodisable] [--abuse-threshold N]
                                          start the node daemon
  status [--config PATH]                  live status screen (mgmt API)
  rotate-keys [--config PATH]             rotate WireGuard identity, print new pubkey for re-register
  report-abuse --reporter R --reason R [--action A] [--ip IP] [--config PATH]
                                          log an abuse complaint (no traffic content recorded)
  blocklist (list|block-ip|unblock-ip|block-key|unblock-key) [VALUE]
                                          manage the persistent operator blocklist

`, nodes.Version)
}
func cmdInitConfig(args []string) {
	fs := flag.NewFlagSet("init-config", flag.ExitOnError)
	cfgPath := fs.String("config", nodes.DefaultPath(), "config file path")
	force := fs.Bool("force", false, "overwrite existing config")
	_ = fs.Parse(args)

	if _, err := os.Stat(*cfgPath); err == nil && !*force {
		fmt.Fprintf(os.Stderr, "config exists at %s (use --force to overwrite)\n", *cfgPath)
		os.Exit(1)
	}
	cfg := nodes.DefaultConfig()
	if err := cfg.Save(*cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, "save config:", err)
		os.Exit(1)
	}
	tok, err := nodes.EnsureMgmtToken("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mgmt token:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s\nmgmt token: %s... (stored in %s)\n", *cfgPath, tok[:8], nodes.MgmtTokenPath())
	fmt.Println("edit region/country/city/max_clients/price/public_endpoint/dero_address, then: veilnet-node run")
}

func buildValidator(cfg *nodes.Config, dev bool) session.TokenValidator {
	if dev || cfg.DevAllowAny {
		return session.AllowAnyExpiryCheckedValidator{DefaultTTL: time.Duration(cfg.MaxSessionMinutes) * time.Minute}
	}
	return session.DenyValidator{Reason: "no token validator configured (payments integration pending; run with --dev for local testing only)"}
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", nodes.DefaultPath(), "config file path")
	dev := fs.Bool("dev", false, "DEV ONLY: accept unsigned tokens with expiry check")
	abuseAuto := fs.Bool("abuse-autodisable", false, "auto emergency-disable after complaint threshold (default off)")
	abuseThreshold := fs.Int("abuse-threshold", nodes.DefaultComplaintThreshold, "complaint count triggering auto-disable")
	_ = fs.Parse(args)

	cfg, err := nodes.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load config:", err)
		os.Exit(1)
	}
	if *dev {
		cfg.DevAllowAny = true
		fmt.Println("WARNING: --dev mode: accepting unsigned tokens (never use in production)")
	}
	token, err := nodes.EnsureMgmtToken("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mgmt token:", err)
		os.Exit(1)
	}

	db, err := nodes.OpenStore("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "open store:", err)
		os.Exit(1)
	}
	defer db.Close()

	ctrl, err := nodes.NewController(cfg, buildValidator(cfg, *dev), nil, db, func(event string, v any) {
		fmt.Printf("[event] %s\n", event)
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "controller:", err)
		os.Exit(1)
	}
	guard, err := nodes.NewAbuseGuard(nodes.AbusePolicy{
		AutoDisable:        *abuseAuto,
		ComplaintThreshold: *abuseThreshold,
	}, nil, nil, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "abuse guard:", err)
		os.Exit(1)
	}
	ctrl.SetAbuseGuard(guard)
	if *abuseAuto {
		fmt.Printf("abuse auto-disable ON (threshold %d complaints)\n", *abuseThreshold)
	}
	if cmds, err := nodes.ApplyFirewall(cfg); err != nil {
		fmt.Println("firewall warnings:", err)
		_ = cmds
	} else {
		fmt.Printf("firewall/nat applied (%d rules)\n", len(cmds))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctrl.StartHeartbeatLoop(ctx, time.Duration(cfg.HeartbeatIntervalSec)*time.Second, nil)
	ctrl.StartSweeper(ctx, 30*time.Second)

	srv := nodes.NewServer(ctrl, token)
	go func() {
		fmt.Printf("veilnet-node %s (%s) mgmt on %s wg=%s region=%s clients=0/%d\n",
			nodes.Version, cfg.NodeType, cfg.MgmtBind, cfg.WGInterface, cfg.Region, cfg.MaxClients)
		if err := srv.Serve(cfg.MgmtBind, cfg.AllowRemote); err != nil && !strings.Contains(err.Error(), "Server closed") {
			fmt.Fprintln(os.Stderr, "mgmt api:", err)
			cancel()
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
		fmt.Println("shutting down")
	case <-ctx.Done():
	}
	_ = srv.Close()
}

func mgmtGet(cfg *nodes.Config, token, path string) (map[string]any, error) {
	url := "http://" + cfg.MgmtBind + path
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("mgmt %s: %s", path, strings.TrimSpace(string(body)))
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cfgPath := fs.String("config", nodes.DefaultPath(), "config file path")
	_ = fs.Parse(args)

	cfg, err := nodes.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load config:", err)
		os.Exit(1)
	}
	tokBytes, err := os.ReadFile(nodes.MgmtTokenPath())
	if err != nil {
		fmt.Println("OFFLINE — no mgmt token; is the node running? (veilnet-node run)")
		os.Exit(1)
	}
	token := strings.TrimSpace(string(tokBytes))
	health, err := mgmtGet(cfg, token, "/health")
	if err != nil {
		fmt.Printf("OFFLINE — %v\nregion=%s endpoint=%s\n", err, cfg.Region, cfg.PublicEndpoint)
		os.Exit(1)
	}
	stats, _ := mgmtGet(cfg, token, "/stats")

	num := func(m map[string]any, k string) string {
		if m == nil {
			return "-"
		}
		v, ok := m[k]
		if !ok {
			return "-"
		}
		switch n := v.(type) {
		case float64:
			if n == float64(int64(n)) {
				return fmt.Sprint(int64(n))
			}
			return fmt.Sprintf("%.4g", n)
		default:
			return fmt.Sprint(v)
		}
	}
	uptime := num(health, "uptime_sec")
	fmt.Printf(`ONLINE  veilnet-node %s (%s)
  region:      %s / %s / %s
  clients:     %s/%s
  bandwidth:   down %d Mbps / up %d Mbps (rx %s B / tx %s B)
  sessions:    today %s
  uptime:      %s s
  dero earned: %s
  load:        %s
`,
		nodes.Version, num(health, "node_type"),
		cfg.Region, cfg.Country, cfg.City,
		num(health, "clients"), num(health, "max_clients"),
		cfg.BandwidthDownMbps, cfg.BandwidthUpMbps, num(stats, "rx_bytes"), num(stats, "tx_bytes"),
		num(stats, "sessions_today"),
		uptime,
		num(stats, "dero_earned"),
		num(stats, "load"),
	)
}

// cmdRotateKeys rotates the node's WireGuard identity: a fresh private
// key is written to the config; the new public key is printed for the
// operator to re-register (registry advertisement + peer updates).
// The daemon must be restarted to use the new identity.
func cmdRotateKeys(args []string) {
	fs := flag.NewFlagSet("rotate-keys", flag.ExitOnError)
	cfgPath := fs.String("config", nodes.DefaultPath(), "config file path")
	_ = fs.Parse(args)

	cfg, err := nodes.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load config:", err)
		os.Exit(1)
	}
	oldPub := ""
	if cfg.WGPrivateKey != "" {
		oldPub, _ = wireguard.PublicKeyFor(cfg.WGPrivateKey)
	}
	priv, pub, err := wireguard.GenerateKeypair()
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate keypair:", err)
		os.Exit(1)
	}
	cfg.WGPrivateKey = priv
	if err := cfg.Save(*cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, "save config:", err)
		os.Exit(1)
	}
	fmt.Printf("rotated WireGuard identity (saved to %s)\n", *cfgPath)
	if oldPub != "" {
		fmt.Printf("old pubkey: %s (revoked on restart)\n", oldPub)
	}
	fmt.Printf("new pubkey: %s\n", pub)
	fmt.Println("next: re-register this pubkey/endpoint in the registry, then restart the daemon")
}
// cmdBlocklist manages the persistent operator blocklist (IP/pubkey).
// Changes persist to blocklist.json. A running daemon loads the file
// once at startup, so restart the daemon to apply CLI-made changes.
func cmdBlocklist(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: veilnet-node blocklist (list|block-ip|unblock-ip|block-key|unblock-key) [VALUE]")
		os.Exit(2)
	}
	bl, err := nodes.NewBlocklist("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "open blocklist:", err)
		os.Exit(1)
	}
	switch args[0] {
	case "list":
		fmt.Println("blocklisted IPs and pubkeys (see blocklist.json):")
		fmt.Printf("%s\n", bl.Describe())
	case "block-ip", "unblock-ip", "block-key", "unblock-key":
		if len(args) < 2 || args[1] == "" {
			fmt.Fprintf(os.Stderr, "blocklist %s requires a VALUE\n", args[0])
			os.Exit(2)
		}
		switch args[0] {
		case "block-ip":
			err = bl.BlockIP(args[1])
		case "unblock-ip":
			err = bl.UnblockIP(args[1])
		case "block-key":
			err = bl.BlockPubkey(args[1])
		case "unblock-key":
			err = bl.UnblockPubkey(args[1])
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "update blocklist:", err)
			os.Exit(1)
		}
		fmt.Printf("blocklist %s %s — persisted; restart the daemon to apply to a running node\n", args[0], args[1])
	default:
		fmt.Fprintf(os.Stderr, "unknown blocklist action %q\n", args[0])
		os.Exit(2)
	}
}

func cmdReportAbuse(args []string) {
	fs := flag.NewFlagSet("report-abuse", flag.ExitOnError)
	cfgPath := fs.String("config", nodes.DefaultPath(), "config file path")
	reporter := fs.String("reporter", "", "complainant contact/identifier (required)")
	reason := fs.String("reason", "", "abuse category, e.g. spam, portscan, dmca (required)")
	action := fs.String("action", "logged", "operator action taken, e.g. logged, blocked, disabled")
	subjectIP := fs.String("ip", "", "subject IP (optional)")
	_ = fs.Parse(args)

	if *reporter == "" || *reason == "" {
		fmt.Fprintln(os.Stderr, "report-abuse: --reporter and --reason are required")
		os.Exit(2)
	}
	clog := nodes.NewComplaintLog("")
	c, err := clog.Report(*reporter, *reason, *action, *subjectIP)
	if err != nil {
		fmt.Fprintln(os.Stderr, "report complaint:", err)
		os.Exit(1)
	}
	fmt.Printf("complaint logged at %s by %s: %s (action: %s)\n",
		c.At.Format(time.RFC3339), c.Reporter, c.Reason, c.Action)
	policy, err := nodes.LoadAbusePolicy("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "load abuse policy:", err)
		os.Exit(1)
	}
	if !policy.AutoDisable {
		fmt.Println("abuse auto-disable is OFF (default): complaint logged for operator review only")
		return
	}
	n, err := clog.Count()
	if err != nil {
		fmt.Fprintln(os.Stderr, "count complaints:", err)
		os.Exit(1)
	}
	threshold := policy.ComplaintThreshold
	if threshold <= 0 {
		threshold = nodes.DefaultComplaintThreshold
	}
	fmt.Printf("complaints: %d (threshold %d)\n", n, threshold)
	if n < threshold {
		return
	}
	cfg, err := nodes.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load config:", err)
		os.Exit(1)
	}
	cfg.EmergencyDisable = true
	if err := cfg.Save(*cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, "save config:", err)
		os.Exit(1)
	}
	fmt.Printf("ABUSE THRESHOLD TRIPPED: emergency_disable persisted to %s — restart the daemon to apply\n", *cfgPath)
}
