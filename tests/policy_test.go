package veilnettest

import (
	"testing"

	"github.com/dero-veilnet/veilnet/tests/ref"
)

func TestPolicySafeDefaults(t *testing.T) {
	p := ref.NewPolicy(nil)
	if p.Kill != ref.KillWhileConnected {
		t.Fatalf("default kill = %s", p.Kill)
	}
	if p.DNS != ref.DNSVeilnet {
		t.Fatalf("default dns = %s", p.DNS)
	}
	if p.IPv6 != ref.IPv6Blocked {
		t.Fatalf("default ipv6 = %s (must block until securely routed)", p.IPv6)
	}
}

func TestKillSwitchStateMachine(t *testing.T) {
	bus := ref.NewBus()
	p := ref.NewPolicy(bus)
	ch := make(chan any, 8)
	bus.Subscribe(ref.KillSwitchEnabled, ch)

	// OFF: direct traffic allowed (user explicitly unprotected).
	if err := p.SetKill(ref.KillOff); err != nil {
		t.Fatalf("SetKill OFF: %v", err)
	}
	if p.BlocksDirect(false) || p.BlocksDirect(true) {
		t.Fatal("OFF must not block")
	}
	// ON_WHILE_CONNECTED: blocks only when the tunnel is up.
	if err := p.SetKill(ref.KillWhileConnected); err != nil {
		t.Fatalf("SetKill: %v", err)
	}
	if p.BlocksDirect(false) {
		t.Fatal("must not block when tunnel down (nothing to protect yet)")
	}
	if !p.BlocksDirect(true) {
		t.Fatal("must block direct egress while connected")
	}
	// ALWAYS_ON: blocks even with the tunnel down.
	if err := p.SetKill(ref.KillAlwaysOn); err != nil {
		t.Fatalf("SetKill: %v", err)
	}
	if !p.BlocksDirect(false) || !p.BlocksDirect(true) {
		t.Fatal("ALWAYS_ON must block in every state")
	}
	if err := p.SetKill("SOMETIMES"); err == nil {
		t.Fatal("unknown kill mode accepted")
	}
	// Arming events observed on the bus.
	armed := 0
	for {
		select {
		case <-ch:
			armed++
		default:
			goto done
		}
	}
done:
	if armed != 2 { // WHILE_CONNECTED + ALWAYS_ON; OFF emits nothing
		t.Fatalf("kill-switch armed events = %d, want 2", armed)
	}
}

func TestDNSModeTransitions(t *testing.T) {
	bus := ref.NewBus()
	p := ref.NewPolicy(bus)
	ch := make(chan any, 8)
	bus.Subscribe(ref.DNSChanged, ch)

	for _, m := range []ref.DNSMode{ref.DNSVeilnet, ref.DNSCustom, ref.DNSDoH} {
		if err := p.SetDNS(m, false); err != nil {
			t.Fatalf("SetDNS %s: %v", m, err)
		}
	}
	// SYSTEM without explicit opt-in is refused: no silent downgrade to
	// potentially hostile LAN/DHCP resolvers.
	if err := p.SetDNS(ref.DNSSystem, false); err == nil {
		t.Fatal("SYSTEM dns without explicit opt-in must fail")
	}
	if p.DNS == ref.DNSSystem {
		t.Fatal("mode changed despite refused transition")
	}
	if err := p.SetDNS(ref.DNSSystem, true); err != nil {
		t.Fatalf("explicit SYSTEM opt-in: %v", err)
	}
	if n := len(ch); n != 4 {
		t.Fatalf("DNS_CHANGED events = %d, want 4", n)
	}
}

func TestIPv6NeverLeaksSilently(t *testing.T) {
	p := ref.NewPolicy(nil)
	// There is no "allow direct IPv6" mode: the type system refuses it.
	if err := p.SetIPv6("DIRECT"); err == nil {
		t.Fatal("direct IPv6 mode must be unrepresentable")
	}
	if err := p.SetIPv6(ref.IPv6Routed); err != nil {
		t.Fatalf("ROUTED: %v", err)
	}
	if p.IPv6 != ref.IPv6Routed {
		t.Fatal("routed mode not applied")
	}
	if err := p.SetIPv6(ref.IPv6Blocked); err != nil {
		t.Fatalf("BLOCKED: %v", err)
	}
}
