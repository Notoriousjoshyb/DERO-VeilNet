package routing

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

type fakeRunner struct {
	mu    sync.Mutex
	calls []string
	fail  map[string]bool
	out   map[string]string
}

func (f *fakeRunner) Run(name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	if f.fail[cmd] {
		return "", fmt.Errorf("fake failure: %s", cmd)
	}
	return f.out[cmd], nil
}

func (f *fakeRunner) joined() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, "\n")
}

func TestRouteCycleSymmetric(t *testing.T) {
	fr := &fakeRunner{}
	m := New(fr, WithStateDir(t.TempDir()))
	if err := m.EnsureDefaultViaTunnel("veilnet", "10.7.0.1", 5); err != nil {
		t.Fatal(err)
	}
	if err := m.EnsurePeerBypass("203.0.113.7", "Ethernet", "192.168.1.1", 1); err != nil {
		t.Fatal(err)
	}
	if len(m.Added()) != 2 {
		t.Fatalf("tracked = %d", len(m.Added()))
	}
	if err := m.RemoveAll(); err != nil {
		t.Fatal(err)
	}
	if len(m.Added()) != 0 {
		t.Fatal("routes must be untracked after RemoveAll")
	}
	log := fr.joined()
	// Every add must have a matching delete (no stale OS state).
	for _, want := range []string{"add route", "delete route"} {
		if !strings.Contains(log, want) {
			t.Fatalf("missing %q in:\n%s", want, log)
		}
	}
	if strings.Count(log, "add route") != strings.Count(log, "delete route") {
		t.Fatalf("add/delete asymmetry:\n%s", log)
	}
}

func TestIPv6BlockRestore(t *testing.T) {
	fr := &fakeRunner{}
	m := New(fr, WithStateDir(t.TempDir()))
	if err := m.BlockIPv6("veilnet"); err != nil {
		t.Fatal(err)
	}
	log := fr.joined()
	if !strings.Contains(log, "::/0") {
		t.Fatalf("IPv6 block must cover ::/0:\n%s", log)
	}
	if err := m.RestoreIPv6(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fr.joined(), "delete rule") {
		t.Fatal("IPv6 block rule must be deleted on restore")
	}
}

func TestCrashRecoveryRemovesStale(t *testing.T) {
	dir := t.TempDir()
	fr := &fakeRunner{}
	m := New(fr, WithStateDir(dir))
	if err := m.EnsureDefaultViaTunnel("veilnet", "10.7.0.1", 5); err != nil {
		t.Fatal(err)
	}
	// Simulate crash: new manager over the same state dir must clean up.
	fr2 := &fakeRunner{}
	_ = New(fr2, WithStateDir(dir))
	if !strings.Contains(fr2.joined(), "delete route") {
		t.Fatalf("stale route not cleaned:\n%s", fr2.joined())
	}
}
