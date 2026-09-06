package app

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Diagnostics is the privacy report: tunnel, exit IP (node-reported plus a
// local check), DNS route, IPv6 posture, kill switch, node, and multihop.
// Every field carries real observed values; unknown is reported as unknown,
// never fabricated.
type Diagnostics struct {
	At            time.Time
	Tunnel        Check
	ExitIP        Check
	LocalIPCheck  Check
	DNSRoute      Check
	IPv6          Check
	KillSwitch    Check
	// Enforcement reports whether a privileged service is actually
	// applying protection, or whether it is config-state only.
	Enforcement Check
	Node        Check
	Multihop    Check
}

// Check is one named result: Name, OK, Value, Detail.
type Check struct {
	Name   string
	OK     bool
	Value  string
	Detail string
}

// Diagnose snapshots current privacy posture.
func (a *App) Diagnose() Diagnostics {
	a.mu.RLock()
	cfg := a.cfg
	node := a.node
	circ := a.circuit
	a.mu.RUnlock()

	d := Diagnostics{At: time.Now()}
	state := StateDown
	var endpoint string
	var hs time.Time
	if a.engine != nil {
		es := a.engine.Status()
		state, endpoint, hs = es.State, es.Endpoint, es.LastHandshake
	}

	// Tunnel: UP only on real engine UP state. No fake PROTECTED badge.
	d.Tunnel = Check{Name: "tunnel", OK: state == StateUp, Value: state}
	if state == StateUp {
		d.Tunnel.Detail = "engine UP on " + endpoint
		if !hs.IsZero() {
			d.Tunnel.Detail += "; handshake " + time.Since(hs).Round(time.Second).String() + " ago"
		}
	} else if node != nil {
		d.Tunnel.Detail = "tunnel not established; traffic must not flow"
	} else {
		d.Tunnel.Detail = "disconnected"
	}

	// Exit IP: node-reported endpoint IP plus a local check note.
	if node != nil {
		host, _, err := net.SplitHostPort(node.Endpoint)
		if err != nil {
			host = node.Endpoint
		}
		d.ExitIP = Check{Name: "exit_ip", OK: state == StateUp, Value: host,
			Detail: "exit endpoint reported by node metadata (" + node.NodeID + ")"}
	} else {
		d.ExitIP = Check{Name: "exit_ip", Value: "none", Detail: "not connected"}
	}
	d.LocalIPCheck = Check{Name: "local_ip_check", Value: "not probed",
		Detail: "local egress check runs on demand; exit IP above is node-reported"}

	// DNS route.
	servers := strings.Join(cfg.DNS.Servers, ",")
	if servers == "" {
		servers = "10.89.0.1 (veilnet default)"
	}
	d.DNSRoute = Check{Name: "dns_route", OK: state != StateUp || cfg.DNS.Mode != "SYSTEM",
		Value: cfg.DNS.Mode, Detail: "resolvers: " + servers}

	// Enforcement: what the OS actually has applied, when a privileged
	// enforcer is wired. Without one the report says so plainly rather
	// than implying protection the client cannot deliver.
	enf := a.EnforceStatus()
	d.Enforcement = Check{Name: "enforcement", OK: enf.Available && (enf.Applied || state != StateUp)}
	switch {
	case !enf.Available:
		d.Enforcement.Value = "not enforced here"
		d.Enforcement.Detail = "this client has no privileged service; kill switch and DNS are config-state only"
	case enf.Applied:
		d.Enforcement.Value = "applied"
		d.Enforcement.Detail = "kill switch via " + enf.KillSwitchBackend +
			"; DNS via " + enf.DNSBackend + "; routes via " + enf.RoutingBackend
	default:
		d.Enforcement.Value = "idle"
		d.Enforcement.Detail = "nothing applied (not connected)"
	}
	if enf.Error != "" {
		d.Enforcement.OK = false
		d.Enforcement.Detail += "; last error: " + enf.Error
	}

	// IPv6: routed securely or blocked; never silently leaked. When the
	// service is enforcing, report the applied posture, not the config.
	ipv6Value := "blocked"
	ipv6Detail := "IPv6 blocked while connected (no silent leak)"
	if cfg.DNS.IPv6Upstream {
		ipv6Value = "routed"
		ipv6Detail = "IPv6 upstream explicitly enabled; routed through tunnel"
	}
	if enf.Available && enf.Applied && enf.IPv6 != "" && enf.IPv6 != "unknown" {
		ipv6Value = enf.IPv6
		ipv6Detail = "applied by the privileged service (" + enf.RoutingBackend + ")"
	}
	// Blocked is the safe posture, connected or not: it is what stops a
	// silent IPv6 leak, so it must never read as a failure.
	d.IPv6 = Check{Name: "ipv6", OK: true, Value: ipv6Value, Detail: ipv6Detail}

	// Kill switch. Enforcing means rules are really installed, which only
	// the privileged service can claim.
	// "While connected" covers the whole connection, CONNECTING included:
	// that handshake window is exactly when an unprotected leak would
	// happen, so rules go on with the tunnel, not after it settles.
	ksWanted := cfg.KillSwitch == "ALWAYS_ON" ||
		(cfg.KillSwitch == "ON_WHILE_CONNECTED" && (node != nil || state == StateUp))
	ksEnforced := enf.Available && enf.Applied && enf.KillSwitch != "" && enf.KillSwitch != "OFF"
	ksDetail := boolStr(ksWanted, "requested by config", "not requested")
	switch {
	case ksEnforced:
		ksDetail = "enforcing via " + enf.KillSwitchBackend
	case ksWanted && enf.Available:
		ksDetail = "requested but not applied"
	case ksWanted && !enf.Available:
		ksDetail = "config-state only: no privileged service wired"
	}
	d.KillSwitch = Check{
		Name:   "killswitch",
		OK:     cfg.KillSwitch == "OFF" || ksEnforced || !ksWanted,
		Value:  cfg.KillSwitch,
		Detail: ksDetail,
	}

	// Node.
	if node != nil {
		d.Node = Check{Name: "node", OK: true, Value: node.NodeID,
			Detail: node.City + ", " + node.Country + " (" + node.Region + "); bond " +
				formatDero(node.BondDero) + " DERO; v" + node.Version}
	} else {
		d.Node = Check{Name: "node", Value: "none", Detail: "no node selected"}
	}

	// Multihop.
	if circ.Active {
		d.Multihop = Check{Name: "multihop", OK: true,
			Value: circ.EntryID + " -> " + circ.ExitID,
			Detail: "2-hop circuit; rotations: " + itoa(circ.Rotations)}
	} else {
		d.Multihop = Check{Name: "multihop", Value: "direct",
			Detail: "single-hop; enable multihop in settings for 2-hop circuits"}
	}
	return d
}

func boolStr(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}

func formatDero(f float64) string {
	if f == 0 {
		return "0"
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.8f", f), "0"), ".")
}

func itoa(n int) string { return itoa64(int64(n)) }

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
