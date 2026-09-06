package security

// Privacy diagnostics engine: seven checks {tunnel, exit IP, DNS route,
// IPv6, kill switch, node, multihop} with OK / WARNING / FAIL / UNKNOWN
// states. WARNING marks degraded-but-working states (e.g. single-hop
// fallback, DNS via system resolver with user consent) so the UI can badge
// precisely instead of a binary private/not-private.
//
// Wording rule (enforced by review, stated here normatively): diagnostics
// MUST never emit "ANONYMOUS", "UNTRACEABLE", or "100% PRIVATE" (or
// equivalents). Highest allowed positive wording is "protected" scoped to
// the component, always alongside the WARNING/FAIL detail when present.

import "strings"

// State is a diagnostic outcome.
type State string

const (
	OK      State = "OK"
	WARNING State = "WARNING"
	FAIL    State = "FAIL"
	UNKNOWN State = "UNKNOWN"
)

// Check is one component verdict.
type Check struct {
	Component string
	State     State
	Detail    string
}

// Inputs are point-in-time observations supplied by the app layer (tunnel
// status, routing tables, config). The engine is pure: no syscalls here,
// so platform probes live with the tunnel/firewall/dns owners.
type Inputs struct {
	TunnelUp        bool
	TunnelState     string // DOWN/CONNECTING/UP/FAILED mirror for detail text
	ExitIP          string
	ExpectedExitIP  string
	DNSRouted       bool // true when DNS exits via the tunnel resolver
	DNSMode         string // VEILNET / CUSTOM / DOH / SYSTEM-explicit-only
	IPv6Blocked     bool
	IPv6Present     bool // true when an unblocked v6 path exists
	KillSwitch      string // OFF / ON_WHILE_CONNECTED / ALWAYS_ON
	NodeBonded      bool
	HopCount        int    // 1 single-hop fallback, 2 standard
	ThreeHopClaimed bool   // must always be false unless flag enabled
}

// RunDiagnostics evaluates all seven components in fixed order.
func RunDiagnostics(in Inputs) []Check {
	return []Check{
		checkTunnel(in),
		checkExitIP(in),
		checkDNS(in),
		checkIPv6(in),
		checkKillSwitch(in),
		checkNode(in),
		checkMultihop(in),
	}
}

func checkTunnel(in Inputs) Check {
	if in.TunnelUp {
		return Check{"tunnel", OK, "tunnel is UP (" + in.TunnelState + ")"}
	}
	return Check{"tunnel", FAIL, "tunnel is not up (" + in.TunnelState + "); traffic is not routed through VeilNet"}
}

func checkExitIP(in Inputs) Check {
	if in.ExitIP == "" {
		return Check{"exit IP", UNKNOWN, "exit IP not yet observed; re-check after handshake"}
	}
	if in.ExpectedExitIP != "" && in.ExitIP != in.ExpectedExitIP {
		return Check{"exit IP", FAIL, "observed exit " + in.ExitIP + " differs from expected " + in.ExpectedExitIP}
	}
	return Check{"exit IP", OK, "traffic exits via " + in.ExitIP}
}

func checkDNS(in Inputs) Check {
	if in.DNSRouted {
		return Check{"dns route", OK, "DNS resolves via the tunnel (" + in.DNSMode + ")"}
	}
	if strings.ToUpper(in.DNSMode) == "SYSTEM" {
		return Check{"dns route", WARNING, "DNS uses the system resolver with your explicit consent; sites you resolve may be visible to the local network"}
	}
	return Check{"dns route", FAIL, "DNS is not routed through the tunnel; fix before relying on exit IP"}
}

func checkIPv6(in Inputs) Check {
	switch {
	case in.IPv6Blocked:
		return Check{"ipv6", OK, "IPv6 is routed through the tunnel or blocked; no bypass path"}
	case in.IPv6Present:
		return Check{"ipv6", FAIL, "an unblocked IPv6 path exists outside the tunnel; traffic may bypass the exit"}
	default:
		return Check{"ipv6", WARNING, "IPv6 state unverified on this network; treated as untrusted until re-check"}
	}
}

func checkKillSwitch(in Inputs) Check {
	switch strings.ToUpper(in.KillSwitch) {
	case "ALWAYS_ON":
		return Check{"killswitch", OK, "kill switch ALWAYS_ON: traffic is blocked unless the tunnel is up"}
	case "ON_WHILE_CONNECTED", "ON":
		return Check{"killswitch", WARNING, "kill switch guards only while connected; disconnects outside a session are not blocked"}
	default:
		return Check{"killswitch", WARNING, "kill switch is OFF; leaks are possible if the tunnel drops — enable ALWAYS_ON for full blocking"}
	}
}

func checkNode(in Inputs) Check {
	if in.NodeBonded {
		return Check{"node", OK, "exit node presents the expected bond/identity"}
	}
	return Check{"node", WARNING, "exit node bond not verified; connection works but node identity is unconfirmed"}
}

func checkMultihop(in Inputs) Check {
	if in.ThreeHopClaimed {
		return Check{"multihop", WARNING, "3-hop display requested but 3-hop is disabled in this build; showing standard 2-hop state"}
	}
	switch in.HopCount {
	case 2:
		return Check{"multihop", OK, "2-hop circuit: entry knows your IP, exit knows the destination (see observability notes)"}
	case 1:
		return Check{"multihop", WARNING, "single-hop fallback: the lone node sees both your IP and destination; rotate to 2-hop when nodes are available"}
	default:
		return Check{"multihop", UNKNOWN, "no circuit established yet"}
	}
}
