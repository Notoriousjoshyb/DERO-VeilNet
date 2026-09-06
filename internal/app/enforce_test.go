package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/dero-veilnet/veilnet/internal/config"
	"github.com/dero-veilnet/veilnet/internal/storage"
)

// fakeEnforcer records calls and can be told to fail on Apply.
type fakeEnforcer struct {
	applyErr error
	clearErr error
	applied  int
	cleared  int
	failed   int
	lastPlan EnforcePlan
	active   bool
}

func (f *fakeEnforcer) Apply(p EnforcePlan) error {
	f.applied++
	f.lastPlan = p
	if f.applyErr != nil {
		return f.applyErr
	}
	f.active = true
	return nil
}

func (f *fakeEnforcer) Clear() error {
	f.cleared++
	f.active = false
	return f.clearErr
}

func (f *fakeEnforcer) FailClosed(string) error {
	f.failed++
	return nil
}

func (f *fakeEnforcer) Status() EnforceStatus {
	return EnforceStatus{Applied: f.active, KillSwitch: "ON_WHILE_CONNECTED",
		DNSMode: "VEILNET", IPv6: "blocked",
		KillSwitchBackend: "fake", DNSBackend: "fake", RoutingBackend: "fake"}
}

func newEnforceApp(t *testing.T) (*App, *fakeEnforcer) {
	t.Helper()
	store, err := storage.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cfg := config.DefaultClientConfig()
	a := New(cfg, store, NewFakeEngine(), NewStaticNodes(append([]NodeInfo(nil), demoNodes...)))
	f := &fakeEnforcer{}
	a.SetEnforcer(f)
	return a, f
}

// A connection must not be reported as established when leak protection
// cannot be applied: the tunnel is torn down and the error surfaces.
func TestConnectFailsClosedWhenEnforcementFails(t *testing.T) {
	a, f := newEnforceApp(t)
	f.applyErr = errors.New("firewall: apply rules: denied")

	err := a.Connect("demo-eu-01")
	if err == nil {
		t.Fatal("connect must fail when leak protection cannot be applied")
	}
	if !strings.Contains(err.Error(), "leak protection failed") {
		t.Fatalf("error must name the cause, got %v", err)
	}
	st := a.State()
	if st.EngineState == StateUp {
		t.Fatal("engine must be stopped after a failed enforcement")
	}
	if st.Node != nil {
		t.Fatal("no node may be recorded after a refused connection")
	}
	if f.cleared == 0 {
		t.Fatal("partial enforcement must be cleared on failure")
	}
}

// The happy path applies protection and clears it again on disconnect.
func TestConnectAppliesAndDisconnectClears(t *testing.T) {
	a, f := newEnforceApp(t)

	if err := a.Connect("demo-eu-01"); err != nil {
		t.Fatal(err)
	}
	if f.applied != 1 {
		t.Fatalf("Apply called %d times, want 1", f.applied)
	}
	if f.lastPlan.EndpointIP != "127.0.0.1" || f.lastPlan.EndpointPort != 51821 {
		t.Fatalf("plan endpoint = %s:%d, want 127.0.0.1:51821",
			f.lastPlan.EndpointIP, f.lastPlan.EndpointPort)
	}
	if f.lastPlan.TunAddr != "10.89.0.2" {
		t.Fatalf("plan tun addr = %q, want 10.89.0.2 (mask stripped)", f.lastPlan.TunAddr)
	}
	if f.lastPlan.RouteIPv6 {
		t.Fatal("IPv6 must default to blocked, never routed by default")
	}
	if f.lastPlan.KillSwitch != config.KillWhileConnected {
		t.Fatalf("plan kill switch = %q, want %q", f.lastPlan.KillSwitch, config.KillWhileConnected)
	}

	if err := a.Disconnect(); err != nil {
		t.Fatal(err)
	}
	if f.cleared != 1 {
		t.Fatalf("Clear called %d times, want 1", f.cleared)
	}
}

// Without an enforcer the client still runs, and diagnostics say plainly
// that nothing is enforced rather than implying protection.
func TestNoEnforcerIsReportedHonestly(t *testing.T) {
	a, _ := newEnforceApp(t)
	a.SetEnforcer(nil)

	if err := a.Connect("demo-eu-01"); err != nil {
		t.Fatal(err)
	}
	d := a.Diagnose()
	if d.Enforcement.OK {
		t.Fatal("enforcement check must not be OK with no enforcer wired")
	}
	if !strings.Contains(d.Enforcement.Value, "not enforced") {
		t.Fatalf("enforcement value = %q, must say it is not enforced", d.Enforcement.Value)
	}
	if !strings.Contains(d.KillSwitch.Detail, "config-state only") {
		t.Fatalf("kill switch detail = %q, must not claim enforcement", d.KillSwitch.Detail)
	}
}

// With an enforcer applied, diagnostics report the real backends.
func TestEnforcedDiagnosticsNameBackends(t *testing.T) {
	a, _ := newEnforceApp(t)
	if err := a.Connect("demo-eu-01"); err != nil {
		t.Fatal(err)
	}
	d := a.Diagnose()
	if !d.Enforcement.OK || d.Enforcement.Value != "applied" {
		t.Fatalf("enforcement = %+v, want applied", d.Enforcement)
	}
	if !strings.Contains(d.KillSwitch.Detail, "enforcing via fake") {
		t.Fatalf("kill switch detail = %q, want the backend named", d.KillSwitch.Detail)
	}
}

func TestResolveEndpointRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:99999", "host:port"} {
		if _, _, err := resolveEndpoint(bad); err == nil {
			t.Fatalf("resolveEndpoint(%q) must fail", bad)
		}
	}
	ip, port, err := resolveEndpoint("203.0.113.7:51820")
	if err != nil || ip != "203.0.113.7" || port != 51820 {
		t.Fatalf("resolveEndpoint = %s,%d,%v", ip, port, err)
	}
}
