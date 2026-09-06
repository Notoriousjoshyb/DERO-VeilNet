package ref

import "errors"

// KillMode mirrors the Contract kill-switch modes.
type KillMode string

const (
	KillOff               KillMode = "OFF"
	KillWhileConnected    KillMode = "ON_WHILE_CONNECTED"
	KillAlwaysOn          KillMode = "ALWAYS_ON"
)

// DNSMode mirrors the Contract DNS modes.
type DNSMode string

const (
	DNSVeilnet DNSMode = "VEILNET"
	DNSCustom  DNSMode = "CUSTOM"
	DNSDoH     DNSMode = "DOH"
	DNSSystem  DNSMode = "SYSTEM"
)

// IPv6Mode: route securely through the tunnel or block entirely.
// There is intentionally no "allow direct" mode: never a silent leak.
type IPv6Mode string

const (
	IPv6Routed IPv6Mode = "ROUTED"
	IPv6Blocked IPv6Mode = "BLOCKED"
)

// Policy is the observable network-safety state machine.
type Policy struct {
	Kill KillMode
	DNS  DNSMode
	IPv6 IPv6Mode
	bus  *Bus
}

// NewPolicy returns safe defaults: kill switch on-while-connected,
// Veilnet DNS, IPv6 blocked until a secure route is confirmed.
func NewPolicy(bus *Bus) *Policy {
	return &Policy{Kill: KillWhileConnected, DNS: DNSVeilnet, IPv6: IPv6Blocked, bus: bus}
}

// SetKill transitions the kill-switch mode, emitting KILL_SWITCH_ENABLED
// whenever protection is armed (any mode except OFF).
func (p *Policy) SetKill(m KillMode) error {
	switch m {
	case KillOff, KillWhileConnected, KillAlwaysOn:
		p.Kill = m
		if m != KillOff && p.bus != nil {
			p.bus.Publish(KillSwitchEnabled, string(m))
		}
		return nil
	default:
		return errors.New("ref: unknown kill mode")
	}
}

// SetDNS transitions DNS handling, emitting DNS_CHANGED. SYSTEM is explicit
// opt-in only: callers must pass explicit=true, mirroring the UI confirm.
func (p *Policy) SetDNS(m DNSMode, explicit bool) error {
	switch m {
	case DNSVeilnet, DNSCustom, DNSDoH, DNSSystem:
		if m == DNSSystem && !explicit {
			return errors.New("ref: SYSTEM dns requires explicit opt-in")
		}
		p.DNS = m
		if p.bus != nil {
			p.bus.Publish(DNSChanged, string(m))
		}
		return nil
	default:
		return errors.New("ref: unknown dns mode")
	}
}

// SetIPv6 selects routed-or-blocked. Direct (leaking) IPv6 is unrepresentable.
func (p *Policy) SetIPv6(m IPv6Mode) error {
	switch m {
	case IPv6Routed, IPv6Blocked:
		p.IPv6 = m
		return nil
	default:
		return errors.New("ref: unknown ipv6 mode (direct ipv6 is never allowed)")
	}
}

// BlocksDirect answers whether non-tunnel egress must be refused given the
// tunnel state. This is the assertion surface for kill-switch tests.
func (p *Policy) BlocksDirect(tunnelUp bool) bool {
	switch p.Kill {
	case KillAlwaysOn:
		return true
	case KillWhileConnected:
		return tunnelUp
	default:
		return false
	}
}
