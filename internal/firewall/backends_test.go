package firewall

import (
	"errors"
	"strings"
	"testing"
)

var errFakeNftMissing = errors.New("fake: nft missing")

func testSpec(lan bool) Spec {
	return Spec{EndpointIP: "203.0.113.7", EndpointPort: 51820, TunAddr: "10.7.0.2", LANAllowed: lan}
}

// Every backend must be symmetric: each owned rule added by Enable is
// removed by Remove/Disable, leaving zero residual rules.

// Windows (netsh) path: rule names are stable and each added rule is
// deleted by name; the snapshotted policy is restored exactly.
func TestWindowsBackendSymmetric(t *testing.T) {
	be := windowsBackend{}
	if !be.Supports() {
		t.Log("windows backend not supported here; still testing command symmetry")
	}
	for _, lan := range []bool{false, true} {
		fr := &fakeRunner{}
		spec := testSpec(lan)
		policy, err := be.CurrentPolicy(fr)
		if err != nil {
			t.Fatal(err)
		}
		if err := be.Enable(fr, spec); err != nil {
			t.Fatal(err)
		}
		names := be.RuleNames(spec)
		if len(names) == 0 {
			t.Fatal("no rule names")
		}
		added := fr.joined()
		for _, n := range names {
			if !strings.Contains(added, n) {
				t.Fatalf("lan=%v: rule %s not added in:\n%s", lan, n, added)
			}
		}
		if err := be.SetBlock(fr); err != nil {
			t.Fatal(err)
		}
		if err := be.Remove(fr, names); err != nil {
			t.Fatal(err)
		}
		if err := be.Restore(fr, policy); err != nil {
			t.Fatal(err)
		}
		final := fr.joined()
		for _, n := range names {
			if !strings.Contains(final, "delete rule name="+n) {
				t.Fatalf("lan=%v: rule %s not deleted in:\n%s", lan, n, final)
			}
		}
		if !strings.Contains(final, "firewallpolicy "+policy) {
			t.Fatalf("policy %q not restored in:\n%s", policy, final)
		}
	}
}

// Linux (nftables) path: one table owns every rule; Disable deletes the
// whole table, so nothing can linger.
func TestLinuxBackendSymmetric(t *testing.T) {
	be := linuxBackend{}
	for _, lan := range []bool{false, true} {
		fr := &fakeRunner{}
		spec := testSpec(lan)
		if err := be.Enable(fr, spec); err != nil {
			t.Fatal(err)
		}
		added := fr.joined()
		for _, want := range []string{
			"add table inet veilnet",
			"203.0.113.7", "51820", "10.7.0.2",
			"255.255.255.255", "policy drop",
		} {
			if !strings.Contains(added, want) {
				t.Fatalf("lan=%v: missing %q in:\n%s", lan, want, added)
			}
		}
		if lan && !strings.Contains(added, "veilnet-ks-lan") {
			t.Fatalf("lan=true: LAN rule missing in:\n%s", added)
		}
		if !lan && strings.Contains(added, "veilnet-ks-lan") {
			t.Fatalf("lan=false: LAN rule must be absent in:\n%s", added)
		}
		if err := be.SetBlock(fr); err != nil {
			t.Fatal(err)
		}
		names := be.RuleNames(spec)
		if err := be.Remove(fr, names); err != nil {
			t.Fatal(err)
		}
		final := fr.joined()
		if !strings.Contains(final, "delete table inet veilnet") {
			t.Fatalf("table not deleted (residual rules) in:\n%s", final)
		}
	}
}

// Linux fallback path: when nft fails, iptables rules carry the same
// allow-list semantics instead of running unprotected.
func TestLinuxBackendIptablesFallback(t *testing.T) {
	be := linuxBackend{}
	fr := &failNftRunner{fakeRunner: &fakeRunner{}}
	spec := testSpec(false)
	if err := be.Enable(fr, spec); err != nil {
		t.Fatalf("fallback must succeed: %v", err)
	}
	log := fr.joined()
	for _, want := range []string{"iptables", "203.0.113.7", "51820", "10.7.0.2", "OUTPUT DROP"} {
		if !strings.Contains(log, want) {
			t.Fatalf("missing %q in:\n%s", want, log)
		}
	}
}

type failNftRunner struct {
	*fakeRunner
}

func (f *failNftRunner) Run(name string, args ...string) (string, error) {
	if name == "nft" {
		return "", errFakeNftMissing
	}
	return f.fakeRunner.Run(name, args...)
}

// macOS (pf) path: the anchor holds the whole allow-list; Disable flushes
// the anchor, so nothing can linger.
func TestDarwinBackendSymmetric(t *testing.T) {
	be := darwinBackend{}
	for _, lan := range []bool{false, true} {
		fr := &fakeRunner{}
		spec := testSpec(lan)
		rules := be.AnchorRules(spec)
		for _, want := range []string{"203.0.113.7", "51820", "10.7.0.2", "255.255.255.255", "block out all"} {
			if !strings.Contains(rules, want) {
				t.Fatalf("lan=%v: anchor missing %q:\n%s", lan, want, rules)
			}
		}
		if lan != strings.Contains(rules, "veilnet-ks-lan") {
			t.Fatalf("lan=%v: LAN section wrong in:\n%s", lan, rules)
		}
		policy, err := be.CurrentPolicy(fr)
		if err != nil {
			t.Fatal(err)
		}
		if err := be.Enable(fr, spec); err != nil {
			t.Fatal(err)
		}
		if log := fr.joined(); !strings.Contains(log, "pfctl") || !strings.Contains(log, pfAnchor) {
			t.Fatalf("anchor not loaded in:\n%s", log)
		}
		if err := be.SetBlock(fr); err != nil {
			t.Fatal(err)
		}
		if err := be.Remove(fr, be.RuleNames(spec)); err != nil {
			t.Fatal(err)
		}
		if err := be.Restore(fr, policy); err != nil {
			t.Fatal(err)
		}
		final := fr.joined()
		if !strings.Contains(final, "-F all") {
			t.Fatalf("anchor not flushed (residual rules) in:\n%s", final)
		}
	}
}

// Unsupported OSes must fail loudly, never fake protection.
func TestUnsupportedBackendFails(t *testing.T) {
	be := unsupportedBackend{os: "plan9"}
	if be.Supports() {
		t.Fatal("unsupported backend must not report Supports")
	}
	if err := be.Enable(&fakeRunner{}, testSpec(false)); err == nil {
		t.Fatal("unsupported backend must refuse Enable")
	}
}
