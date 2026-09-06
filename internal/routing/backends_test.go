package routing

import (
	"strings"
	"testing"
)

// Linux path: `ip route` add/del mirror each other; IPv6 blackhole is
// added and removed symmetrically.
func TestLinuxBackendSymmetric(t *testing.T) {
	be := linuxBackend{}
	fr := &fakeRunner{}
	r := Route{Dest: "0.0.0.0/0", Gateway: "10.7.0.1", Iface: "veilnet", Metric: 5}
	if err := be.Add(fr, r); err != nil {
		t.Fatal(err)
	}
	if log := fr.joined(); !strings.Contains(log, "ip route add 0.0.0.0/0 via 10.7.0.1 dev veilnet metric 5") {
		t.Fatalf("add wrong in:\n%s", log)
	}
	if err := be.Delete(fr, r); err != nil {
		t.Fatal(err)
	}
	if log := fr.joined(); !strings.Contains(log, "ip route del 0.0.0.0/0 via 10.7.0.1 dev veilnet") {
		t.Fatalf("delete wrong in:\n%s", log)
	}
	if _, err := be.GetMetric(fr, "veilnet"); err == nil {
		t.Fatal("linux metric query must report unsupported, not fake a value")
	}
	if err := be.BlockIPv6(fr, "veilnet"); err != nil {
		t.Fatal(err)
	}
	if err := be.RestoreIPv6(fr); err != nil {
		t.Fatal(err)
	}
	log := fr.joined()
	if !strings.Contains(log, "route add blackhole ::/0") ||
		!strings.Contains(log, "route del blackhole ::/0") {
		t.Fatalf("IPv6 block/restore asymmetric in:\n%s", log)
	}
}

// macOS path: BSD `route` add/delete mirror each other; metrics are an
// explicit error, never a silent no-op.
func TestDarwinBackendSymmetric(t *testing.T) {
	be := darwinBackend{}
	fr := &fakeRunner{}
	def := Route{Dest: "0.0.0.0/0", Gateway: "10.7.0.1", Iface: "utun9", Metric: 5}
	bypass := Route{Dest: "203.0.113.7/32", Gateway: "192.168.1.1", Iface: "en0", Metric: 1}
	if err := be.Add(fr, def); err != nil {
		t.Fatal(err)
	}
	if err := be.Add(fr, bypass); err != nil {
		t.Fatal(err)
	}
	if err := be.Delete(fr, bypass); err != nil {
		t.Fatal(err)
	}
	if err := be.Delete(fr, def); err != nil {
		t.Fatal(err)
	}
	log := fr.joined()
	for _, want := range []string{
		"route -n add -inet default 10.7.0.1",
		"route -n add -inet 203.0.113.7 192.168.1.1",
		"route -n delete -inet 203.0.113.7 192.168.1.1",
		"route -n delete -inet default 10.7.0.1",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("missing %q in:\n%s", want, log)
		}
	}
	if strings.Count(log, "route -n add") != strings.Count(log, "route -n delete") {
		t.Fatalf("add/delete asymmetry in:\n%s", log)
	}
	if err := be.SetMetric(fr, "utun9", 5); err == nil {
		t.Fatal("darwin metric must be an explicit error, not a silent no-op")
	}
	if err := be.BlockIPv6(fr, "utun9"); err != nil {
		t.Fatal(err)
	}
	if err := be.RestoreIPv6(fr); err != nil {
		t.Fatal(err)
	}
	if after := fr.joined(); !strings.Contains(after, "-inet6 ::/0") {
		t.Fatalf("IPv6 blackhole missing in:\n%s", after)
	}
}

// Manager delegates to injected backends: full cycle leaves nothing.
func TestManagerBackendCycles(t *testing.T) {
	for _, be := range []Backend{linuxBackend{}, darwinBackend{}} {
		fr := &fakeRunner{}
		m := New(fr, WithStateDir(t.TempDir()), WithBackend(be))
		if m.BackendName() != be.Name() {
			t.Fatalf("backend = %s", m.BackendName())
		}
		if err := m.EnsureDefaultViaTunnel("veilnet", "10.7.0.1", 5); err != nil {
			t.Fatalf("%s: %v", be.Name(), err)
		}
		if err := m.EnsurePeerBypass("203.0.113.7", "eth0", "192.168.1.1", 1); err != nil {
			t.Fatalf("%s: %v", be.Name(), err)
		}
		if err := m.BlockIPv6("veilnet"); err != nil {
			t.Fatalf("%s: %v", be.Name(), err)
		}
		if err := m.RemoveAll(); err != nil {
			t.Fatalf("%s: %v", be.Name(), err)
		}
		if len(m.Added()) != 0 {
			t.Fatalf("%s: routes linger", be.Name())
		}
	}
}

// Unsupported OSes must fail loudly, never leak traffic unrouted.
func TestUnsupportedBackendFails(t *testing.T) {
	be := unsupportedBackend{os: "plan9"}
	if be.Supports() {
		t.Fatal("unsupported backend must not report Supports")
	}
	m := New(&fakeRunner{}, WithStateDir(t.TempDir()), WithBackend(be))
	if err := m.EnsureDefaultViaTunnel("veilnet", "10.7.0.1", 5); err == nil {
		t.Fatal("unsupported backend must refuse routes")
	}
}
