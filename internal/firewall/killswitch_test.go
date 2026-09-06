package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/dero-veilnet/veilnet/internal/events"
)

type fakeRunner struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeRunner) Run(name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	// netsh show allprofiles: report default allow-outbound policy.
	if strings.Contains(strings.Join(args, " "), "show allprofiles") {
		return "Firewall Policy  BlockInbound,AllowOutbound\n", nil
	}
	return "", nil
}

func (f *fakeRunner) joined() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, "\n")
}

func TestKillSwitchCycleLeavesNothing(t *testing.T) {
	fr := &fakeRunner{}
	m := New(fr, WithStateDir(t.TempDir()))
	got := make(chan any, 2)
	events.Subscribe(events.KILL_SWITCH_ENABLED, got)

	if err := m.Enable(ON_WHILE_CONNECTED, "203.0.113.7", 51820, "10.7.0.2"); err != nil {
		t.Fatal(err)
	}
	if !m.Active() || m.Mode() != ON_WHILE_CONNECTED {
		t.Fatal("manager must be active")
	}
	select {
	case <-got:
	default:
		t.Fatal("missing KILL_SWITCH_ENABLED event")
	}
	log := fr.joined()
	for _, want := range []string{
		"VeilNet-KS-Allow-Endpoint", "remoteip=203.0.113.7", "remoteport=51820",
		"VeilNet-KS-Allow-Tunnel-Out", "localip=10.7.0.2",
		"VeilNet-KS-Allow-DHCP", "firewallpolicy blockinbound,blockoutbound",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("missing %q in:\n%s", want, log)
		}
	}

	if err := m.Disable(); err != nil {
		t.Fatal(err)
	}
	if m.Active() {
		t.Fatal("manager must be idle after Disable")
	}
	after := fr.joined()
	// Every added rule is deleted by name; policy restored; sentinel gone.
	for _, name := range []string{"VeilNet-KS-Allow-Endpoint", "VeilNet-KS-Allow-Tunnel-Out",
		"VeilNet-KS-Allow-Tunnel-In", "VeilNet-KS-Allow-DHCP-Out", "VeilNet-KS-Allow-DHCP-In"} {
		if !strings.Contains(after, "delete rule name="+name) {
			t.Fatalf("stale rule %s in:\n%s", name, after)
		}
	}
	if !strings.Contains(after, "firewallpolicy blockinbound,allowoutbound") {
		t.Fatalf("policy not restored in:\n%s", after)
	}
}

func TestFailClosedKeepsRules(t *testing.T) {
	fr := &fakeRunner{}
	m := New(fr, WithStateDir(t.TempDir()))
	if err := m.Enable(ON_WHILE_CONNECTED, "203.0.113.7", 51820, "10.7.0.2"); err != nil {
		t.Fatal(err)
	}
	n := len(fr.calls)
	if err := m.FailClosed("handshake lost"); err != nil {
		t.Fatal(err)
	}
	if !m.Active() {
		t.Fatal("fail-closed must keep rules active")
	}
	after := fr.joined()
	if strings.Count(after, "delete rule") != 0 {
		t.Fatalf("fail-closed must not delete rules:\n%s", after)
	}
	if len(fr.calls) <= n {
		t.Fatal("fail-closed must re-assert the block policy")
	}
}

func TestStaleSentinelRecovered(t *testing.T) {
	dir := t.TempDir()
	fr := &fakeRunner{}
	m := New(fr, WithStateDir(dir))
	if err := m.Enable(ALWAYS_ON, "203.0.113.7", 51820, "10.7.0.2"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, sentinelName)); err != nil {
		t.Fatal("sentinel must exist while active")
	}
	// Simulate crash: a fresh manager must remove the stale rules first.
	fr2 := &fakeRunner{}
	m2 := New(fr2, WithStateDir(dir))
	if err := m2.Enable(ON_WHILE_CONNECTED, "198.51.100.9", 51820, "10.7.0.2"); err != nil {
		t.Fatal(err)
	}
	log := fr2.joined()
	if !strings.Contains(log, "delete rule name=VeilNet-KS-Allow-Endpoint") {
		t.Fatalf("stale rules not cleaned first:\n%s", log)
	}
	if !strings.Contains(log, "remoteip=198.51.100.9") {
		t.Fatalf("new endpoint not applied:\n%s", log)
	}
	_ = m2.Disable()
}

func TestEnableValidation(t *testing.T) {
	m := New(&fakeRunner{}, WithStateDir(t.TempDir()))
	if err := m.Enable(ON_WHILE_CONNECTED, "", 51820, "10.7.0.2"); err == nil {
		t.Fatal("empty endpoint must fail")
	}
	if err := m.Enable(ON_WHILE_CONNECTED, "203.0.113.7", 0, "10.7.0.2"); err == nil {
		t.Fatal("bad port must fail")
	}
	if err := m.Enable(ON_WHILE_CONNECTED, "203.0.113.7", 51820, ""); err == nil {
		t.Fatal("empty tunnel addr must fail")
	}
	if err := m.Disable(); err != nil {
		t.Fatal("idle Disable must be nil")
	}
}
