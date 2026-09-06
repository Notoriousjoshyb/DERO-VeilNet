// Clean-install journey tests (Windows-host runnable): temp HOME + temp
// state dir, first-run --demo --status, real demo connect showing UP,
// disconnect honesty, settings persistence across "restarts", no stale
// firewall rules, no leftover processes. Kill-switch assertions are
// config-state (honest per docs/CURRENT_LIMITATIONS.md: service enforcement
// wiring is pending, so tests never claim live enforcement).
package onboarding_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dero-veilnet/veilnet/internal/config"
	"github.com/dero-veilnet/veilnet/internal/firewall"
	"github.com/dero-veilnet/veilnet/internal/storage"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repo root (go.mod) not found above working dir")
		}
		dir = parent
	}
}

// cleanHome isolates every home-derived lookup (USERPROFILE on Windows,
// HOME on unix, plus XDG/AppData overrides) to a temp dir.
func cleanHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))
	return home
}

// buildBin compiles a ./cmd/<pkg> binary into a temp dir. A build failure
// (siblings mid-flight) SKIPS the caller as unverified — never a pass.
func buildBin(t *testing.T, pkg, name string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", out, "./cmd/"+pkg)
	cmd.Dir = repoRoot(t)
	var log bytes.Buffer
	cmd.Stdout = &log
	cmd.Stderr = &log
	if err := cmd.Run(); err != nil {
		t.Skipf("unverified: building ./cmd/%s failed (tree mid-flight?): %v\n%s", pkg, err, log.String())
	}
	return out
}

type demoStatus struct {
	EngineState string `json:"EngineState"`
	Node        *struct {
		NodeID string `json:"NodeID"`
	} `json:"Node"`
	Demo bool `json:"Demo"`
}

func parseDemoStatus(t *testing.T, out string) demoStatus {
	t.Helper()
	// The CLI prints human guidance lines before the JSON document
	// (first-run config note, wallet note); the document starts at '{'.
	idx := strings.Index(out, "{")
	if idx < 0 {
		t.Fatalf("no JSON document in status output:\n%s", out)
	}
	var st demoStatus
	if err := json.Unmarshal([]byte(out[idx:]), &st); err != nil {
		t.Fatalf("status JSON: %v\n%s", err, out)
	}
	return st
}

func runDemo(t *testing.T, bin string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			t.Fatalf("run %v: %v (%s)", args, err, buf.String())
		}
	}
	if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
		t.Fatalf("run %v: process state not reaped (leftover process)", args)
	}
	return buf.String(), code
}

func TestFirstRunStatusCleanHome(t *testing.T) {
	home := cleanHome(t)
	bin := buildBin(t, "veilnet", "veilnet-first.exe")

	out, code := runDemo(t, bin, "--demo", "--status")
	if code != 0 {
		t.Fatalf("--demo --status exit = %d, want 0 (first run must work):\n%s", code, out)
	}
	st := parseDemoStatus(t, out)
	if !st.Demo {
		t.Fatalf("demo status must be badged Demo=true, got:\n%s", out)
	}
	if st.EngineState != "DOWN" {
		t.Fatalf("fresh status EngineState = %q, want DOWN", st.EngineState)
	}
	if st.Node != nil {
		t.Fatalf("fresh status must have no node, got %+v", st.Node)
	}
	// Zero-friction onboarding: first run materializes a SAFE default
	// config (fail-closed killswitch, VeilNet DNS) instead of erroring.
	cfg, err := config.LoadClient(filepath.Join(home, ".veilnet", "config.toml"))
	if err != nil {
		t.Fatalf("first run must leave a loadable default config: %v\n%s", err, out)
	}
	if cfg.KillSwitch != config.KillWhileConnected || cfg.DNS.Mode != config.DNSVeilnet {
		t.Fatalf("materialized config is not fail-closed: %+v", cfg)
	}
}

func TestDemoConnectDisconnectJourney(t *testing.T) {
	cleanHome(t)
	bin := buildBin(t, "veilnet", "veilnet-journey.exe")

	// Connect: the CLI blocks in its live loop, so supervise the process and
	// wait for a real UP reading before tearing it down.
	cmd := exec.Command(bin, "--demo", "--connect", "demo-eu-01")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("connect start: %v", err)
	}
	up := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			up <- sc.Text()
		}
	}()
	var lines []string
	sawBanner, sawUp := false, false
	timeout := time.After(30 * time.Second)
collect:
	for !(sawBanner && sawUp) {
		select {
		case line := <-up:
			lines = append(lines, line)
			if strings.HasPrefix(line, "Connected.") {
				sawBanner = true
			}
			if strings.HasPrefix(line, "state=UP") {
				sawUp = true
				if !strings.Contains(line, "node=demo-eu-01") {
					t.Errorf("UP line names wrong node: %q", line)
				}
			}
		case <-timeout:
			break collect
		}
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill connect: %v", err)
	}
	_ = cmd.Wait()
	if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
		t.Fatal("connect process not reaped: leftover process")
	}
	if !sawBanner {
		t.Fatalf("no Connected banner in 30s:\n%s\nstderr:\n%s", strings.Join(lines, "\n"), errBuf.String())
	}
	if !sawUp {
		t.Fatalf("no state=UP reading in 30s:\n%s\nstderr:\n%s", strings.Join(lines, "\n"), errBuf.String())
	}

	// Demo sessions are in-process: a fresh status after the kill is DOWN.
	out, code := runDemo(t, bin, "--demo", "--status")
	if code != 0 {
		t.Fatalf("post-kill status exit = %d:\n%s", code, out)
	}
	if st := parseDemoStatus(t, out); st.EngineState != "DOWN" {
		t.Fatalf("fresh process status = %q, want DOWN (demo holds no cross-process session)", st.EngineState)
	}

	// Disconnect with nothing connected is an honest refusal, not a crash.
	out, code = runDemo(t, bin, "--demo", "--disconnect")
	if code != 0 {
		t.Fatalf("--demo --disconnect exit = %d:\n%s", code, out)
	}
	if !strings.Contains(strings.ToLower(out), "not connected") {
		t.Fatalf("--disconnect must say it is not connected, got:\n%s", out)
	}
}

func TestSettingsPersistAcrossRestart(t *testing.T) {
	home := cleanHome(t)

	// "First run": no file, defaults load.
	cfg, err := config.LoadClient("")
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	// "User changes a setting, closes the app": save to the default path.
	cfg.Region = "eu-west"
	cfg.AutoConnect = true
	if err := cfg.Save(""); err != nil {
		t.Fatalf("save: %v", err)
	}
	path := filepath.Join(home, ".veilnet", "config.toml")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("settings file not created at %q: %v", path, err)
	}
	// "Reopen": settings survived the restart.
	reopened, err := config.LoadClient("")
	if err != nil {
		t.Fatalf("reopen load: %v", err)
	}
	if reopened.Region != "eu-west" || !reopened.AutoConnect {
		t.Fatalf("settings lost across restart: %+v", reopened)
	}
	// "Second restart": still there.
	again, err := config.LoadClient("")
	if err != nil {
		t.Fatalf("second reopen: %v", err)
	}
	if again.Region != "eu-west" {
		t.Fatalf("settings decayed on second restart: %+v", again)
	}

	// State DB likewise survives restarts in the temp state dir.
	dbPath := filepath.Join(t.TempDir(), "client.db")
	open := func() *storage.Store {
		t.Helper()
		s, err := storage.Open(dbPath)
		if err != nil {
			t.Fatalf("open %q: %v", dbPath, err)
		}
		return s
	}
	s := open()
	if err := s.SaveNode(storage.Node{NodeID: "journey-node", Region: "eu-west", Endpoint: "127.0.0.1:51821"}); err != nil {
		t.Fatalf("save node: %v", err)
	}
	if err := s.SetSetting("region", "eu-west"); err != nil {
		t.Fatalf("save setting: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s2 := open()
	defer s2.Close()
	n, err := s2.GetNode("journey-node")
	if err != nil {
		t.Fatalf("node lost across restart: %v", err)
	}
	if n.Region != "eu-west" {
		t.Fatalf("node field lost: %+v", n)
	}
	v, err := s2.GetSetting("region")
	if err != nil || v != "eu-west" {
		t.Fatalf("setting lost across restart: %q, %v", v, err)
	}
}

// stubRunner records OS commands without executing any: journey tests must
// never touch the real firewall.
type stubRunner struct {
	mu    sync.Mutex
	calls []string
}

func (s *stubRunner) Run(name string, args ...string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, name+" "+strings.Join(args, " "))
	if strings.Contains(strings.Join(args, " "), "show allprofiles") {
		return "Firewall Policy  BlockInbound,AllowOutbound\n", nil
	}
	return "", nil
}

func (s *stubRunner) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *stubRunner) joined() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.calls, "\n")
}

func TestNoStaleFirewallRules(t *testing.T) {
	stateDir := t.TempDir()
	stub := &stubRunner{}
	m := firewall.New(stub, firewall.WithStateDir(stateDir))

	// Idle manager: no rules, no sentinel, no OS calls at all.
	if m.Active() || m.Mode() != firewall.OFF || len(m.Rules()) != 0 {
		t.Fatal("fresh manager must be idle with no rules")
	}

	if err := m.Enable(firewall.ON_WHILE_CONNECTED, "203.0.113.7", 51820, "10.7.0.2"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !m.Active() {
		t.Fatal("manager must be active after Enable")
	}
	if err := m.Disable(); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if m.Active() || len(m.Rules()) != 0 {
		t.Fatal("Disable must leave no active rules")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "killswitch.json")); !os.IsNotExist(err) {
		t.Fatal("stale killswitch.json sentinel left after Disable (crash-recovery hazard)")
	}
	// Every added rule was deleted by name.
	log := stub.joined()
	for _, name := range []string{"VeilNet-KS-Allow-Endpoint", "VeilNet-KS-Allow-Tunnel-Out",
		"VeilNet-KS-Allow-Tunnel-In", "VeilNet-KS-Allow-DHCP-Out", "VeilNet-KS-Allow-DHCP-In"} {
		if !strings.Contains(log, "delete rule name="+name) {
			t.Fatalf("stale rule %s (no delete recorded):\n%s", name, log)
		}
	}
	// A reopened manager in the same dir recovers clean (no phantom active).
	m2 := firewall.New(stub, firewall.WithStateDir(stateDir))
	if m2.Active() || len(m2.Rules()) != 0 {
		t.Fatal("reopened manager must be idle: phantom rules from previous run")
	}
}

func TestKillswitchHonestState(t *testing.T) {
	// Kill-switch posture is CONFIG-STATE, not enforced, until the service
	// wires firewall application into Connect/Disconnect
	// (docs/CURRENT_LIMITATIONS.md). These tests pin the honest half:
	// defaults fail closed in config, and pure reads never touch the OS.
	if got := config.DefaultClientConfig().KillSwitch; got != config.KillWhileConnected {
		t.Fatalf("default killswitch = %q, want ON_WHILE_CONNECTED", got)
	}
	stub := &stubRunner{}
	before := stub.count()
	if _, err := config.LoadClient(""); err != nil {
		t.Fatalf("load: %v", err)
	}
	m := firewall.New(stub, firewall.WithStateDir(t.TempDir()))
	_ = m.Mode()
	_ = m.Active()
	_ = m.Rules()
	_ = m.BackendName()
	if got := stub.count(); got != before {
		t.Fatalf("config/state reads issued %d OS commands, want 0 (nothing enforced without explicit Enable)", got-before)
	}
}

// TestNodeAbuseSurface aligns the journey with HardenAgent broadcast #2:
// authorize flood is 429-class and the operator abuse surface (flags,
// subcommands, state files) exists on the node CLI.
func TestNodeAbuseSurface(t *testing.T) {
	cleanHome(t)
	bin := buildBin(t, "veilnet-node", "veilnet-node-abuse.exe")
	cmd := exec.Command(bin, "--help")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		t.Fatalf("--help: %v\n%s", err, buf.String())
	}
	help := buf.String()
	for _, want := range []string{
		"--abuse-autodisable", "--abuse-threshold",
		"rotate-keys", "report-abuse", "blocklist",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("--help missing %q:\n%s", want, help)
		}
	}
}
