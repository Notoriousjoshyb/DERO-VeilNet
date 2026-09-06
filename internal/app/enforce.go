// Leak-protection enforcement hook.
//
// The orchestrator decides WHAT must be enforced for a connection (kill
// switch mode, DNS resolvers, IPv6 posture); the privileged service
// supplies an Enforcer that actually applies it to the OS. Keeping the
// seam here means the GUI-side App (no privileges) and the tests can run
// with no Enforcer at all, while the service wires the real one.
//
// Binding rule: enforcement is fail-closed. If Apply fails on connect the
// tunnel is torn down again and the error is returned, because a session
// that reports PROTECTED without its kill switch and DNS in place is
// exactly the silent leak this project refuses to ship.
package app

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// EnforcePlan is the full leak-protection request for one connection.
// Every field is derived from the live node plus client config; nothing
// is inferred inside the Enforcer.
type EnforcePlan struct {
	// KillSwitch is a config.Kill* value (OFF/ON_WHILE_CONNECTED/ALWAYS_ON).
	KillSwitch string
	// EndpointIP/EndpointPort is the WireGuard peer, which must stay
	// reachable while everything else is blocked.
	EndpointIP   string
	EndpointPort int
	// TunAddr is the local tunnel address (no mask). TunIface is the OS
	// interface name the tunnel uses.
	TunAddr  string
	TunIface string
	// DNSMode is a config.DNS* value; DNSServers are the resolvers to set.
	DNSMode    string
	DNSServers []string
	// RouteIPv6 false means IPv6 must be blocked, never left to leak.
	RouteIPv6 bool
}

// EnforceStatus is the observable enforcement state. It reports what the
// OS actually has applied, not what the config asked for.
type EnforceStatus struct {
	// Available is false when no Enforcer is wired (GUI-only client): the
	// UI must then say "not enforced here", never imply protection.
	Available bool
	Applied   bool
	// KillSwitch/DNSMode/IPv6 describe the applied state.
	KillSwitch string
	DNSMode    string
	IPv6       string
	// Backend names come from the OS layers (netsh/nftables/pf, NRPT/
	// resolved/scutil) and are shown in diagnostics.
	KillSwitchBackend string
	DNSBackend        string
	RoutingBackend    string
	// Error is the last enforcement failure, in user-facing words.
	Error string
}

// Enforcer applies leak protection to the operating system.
type Enforcer interface {
	// Apply installs kill switch, DNS and IPv6 posture for the plan. It
	// must be atomic in effect: on error it undoes its own partial work.
	Apply(p EnforcePlan) error
	// Clear removes everything Apply installed and restores the previous
	// OS state. It is idempotent.
	Clear() error
	// FailClosed re-asserts the block policy after unexpected tunnel loss.
	FailClosed(reason string) error
	// Status reports the applied state for diagnostics.
	Status() EnforceStatus
}

// SetEnforcer injects the OS enforcement layer. Passing nil disables
// enforcement, which the UI reports honestly as "not enforced here".
func (a *App) SetEnforcer(e Enforcer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enforcer = e
}

// EnforceStatus reports the live enforcement state.
func (a *App) EnforceStatus() EnforceStatus {
	a.mu.RLock()
	e := a.enforcer
	a.mu.RUnlock()
	if e == nil {
		return EnforceStatus{Available: false}
	}
	st := e.Status()
	st.Available = true
	return st
}

// buildEnforcePlan derives the plan from the node being connected and the
// current client config. A plan that cannot be built is an error, never a
// silently weaker plan.
func (a *App) buildEnforcePlan(node NodeInfo, tunAddrCIDR string) (EnforcePlan, error) {
	a.mu.RLock()
	cfg := a.cfg
	a.mu.RUnlock()

	ip, port, err := resolveEndpoint(node.Endpoint)
	if err != nil {
		return EnforcePlan{}, err
	}

	servers := cfg.DNS.Servers
	if cfg.DNS.Mode == "VEILNET" || len(servers) == 0 {
		servers = []string{veilnetResolver}
	}

	return EnforcePlan{
		KillSwitch:   cfg.KillSwitch,
		EndpointIP:   ip,
		EndpointPort: port,
		TunAddr:      stripMask(tunAddrCIDR),
		TunIface:     tunnelIfaceName,
		DNSMode:      cfg.DNS.Mode,
		DNSServers:   servers,
		RouteIPv6:    cfg.DNS.IPv6Upstream,
	}, nil
}

// tunnelIfaceName mirrors tunnel.IfaceName. It is duplicated rather than
// imported because internal/app must not depend on internal/tunnel (the
// engine arrives through an interface).
const tunnelIfaceName = "veilnet"

// veilnetResolver is the in-tunnel resolver used by DNS mode VEILNET.
const veilnetResolver = "10.89.0.1"

// resolveEndpoint splits host:port and resolves a hostname to one IP.
// The kill switch needs a literal address: a hostname punched through the
// firewall would be re-resolved outside the tunnel.
func resolveEndpoint(endpoint string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(endpoint))
	if err != nil {
		return "", 0, fmt.Errorf("bad node endpoint %q: %w", endpoint, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("bad node endpoint port in %q", endpoint)
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), port, nil
	}
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		return "", 0, fmt.Errorf("cannot resolve node endpoint host %q: %w", host, err)
	}
	// Prefer IPv4: the firewall rules and the CGNAT plane are v4.
	for _, a := range addrs {
		if a.To4() != nil {
			return a.String(), port, nil
		}
	}
	return addrs[0].String(), port, nil
}

// stripMask turns "10.89.0.2/32" into "10.89.0.2".
func stripMask(addr string) string {
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		return addr[:i]
	}
	return addr
}

// applyEnforcement runs the Enforcer for node. It returns nil when no
// Enforcer is wired: an unprivileged client is allowed to run, and the UI
// says so rather than pretending.
func (a *App) applyEnforcement(node NodeInfo, tunAddrCIDR string) error {
	a.mu.RLock()
	e := a.enforcer
	a.mu.RUnlock()
	if e == nil {
		return nil
	}
	plan, err := a.buildEnforcePlan(node, tunAddrCIDR)
	if err != nil {
		return err
	}
	if err := e.Apply(plan); err != nil {
		return fmt.Errorf("leak protection failed, tunnel refused: %w", err)
	}
	return nil
}

// ClearEnforcement removes any OS enforcement left in place. The service
// calls it at startup so a crashed previous run cannot leave the machine
// half-blocked.
func (a *App) ClearEnforcement() error { return a.clearEnforcement() }

// clearEnforcement removes OS enforcement. Errors are returned so the
// caller can surface them; the tunnel is already down by then.
func (a *App) clearEnforcement() error {
	a.mu.RLock()
	e := a.enforcer
	a.mu.RUnlock()
	if e == nil {
		return nil
	}
	return e.Clear()
}

// FailClosed re-asserts the block policy after unexpected tunnel loss.
// The watchdog and the service call it; it never lifts rules.
func (a *App) FailClosed(reason string) error {
	a.mu.RLock()
	e := a.enforcer
	a.mu.RUnlock()
	if e == nil {
		return errors.New("no enforcer wired")
	}
	return e.FailClosed(reason)
}
