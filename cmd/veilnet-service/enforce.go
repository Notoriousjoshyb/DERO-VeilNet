// OS leak-protection enforcement, applied by the privileged service.
//
// This is the piece that makes the kill switch, DNS mode and IPv6 posture
// real rather than config-state: on Connect the service installs firewall
// rules, sets tunnel resolvers, and blocks IPv6 unless the user opted into
// routing it; on Disconnect it puts everything back.
//
// Order matters. Applying is: firewall → DNS → IPv6, because the firewall
// is what keeps the box safe if a later step fails. Clearing is the exact
// reverse. Any failure inside Apply rolls back the steps already done, so
// the caller never sees a half-enforced machine.
package main

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dero-veilnet/veilnet/internal/app"
	"github.com/dero-veilnet/veilnet/internal/dns"
	"github.com/dero-veilnet/veilnet/internal/firewall"
	"github.com/dero-veilnet/veilnet/internal/routing"
)

// osEnforcer applies app.EnforcePlan through the per-OS backends.
type osEnforcer struct {
	mu sync.Mutex

	kill  *firewall.Manager
	route *routing.Manager
	// dnsMgr is rebuilt per apply because dns.Manager binds an interface
	// name at construction.
	dnsMgr *dns.Manager

	applied    bool
	killMode   string
	dnsMode    string
	ipv6       string
	lastErr    string
	dnsBackend string
}

// newEnforcer builds the production enforcer over real OS runners.
func newEnforcer() *osEnforcer {
	run := firewall.ExecRunner{Timeout: 30 * time.Second}
	return &osEnforcer{
		kill:  firewall.New(run),
		route: routing.New(routing.ExecRunner{Timeout: 30 * time.Second}),
		ipv6:  "unknown",
	}
}

// Apply installs the full posture described by p.
func (e *osEnforcer) Apply(p app.EnforcePlan) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Re-applying over a previous session is legal (reconnect): clear
	// first so rules never stack.
	if e.applied {
		e.clearLocked()
	}

	var undo []func()
	rollback := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}

	// 1. Kill switch. OFF is a real choice, not a failure.
	if mode := firewall.Mode(p.KillSwitch); mode != firewall.OFF && p.KillSwitch != "" {
		if err := e.kill.Enable(mode, p.EndpointIP, p.EndpointPort, p.TunAddr); err != nil {
			e.fail(err)
			return err
		}
		undo = append(undo, func() { _ = e.kill.Disable() })
	}

	// 2. DNS. SYSTEM is explicit opt-in and applies no tunnel resolvers.
	e.dnsMgr = dns.New(dns.ExecRunner{Timeout: 30 * time.Second}, p.TunIface)
	e.dnsBackend = e.dnsMgr.BackendName()
	if err := e.dnsMgr.Apply(dns.Mode(p.DNSMode), p.DNSServers); err != nil {
		rollback()
		e.fail(err)
		return err
	}
	undo = append(undo, func() { _ = e.dnsMgr.Restore() })

	// 3. IPv6: routed only when the user explicitly asked for it,
	// otherwise blocked so it cannot escape the tunnel.
	if p.RouteIPv6 {
		e.ipv6 = "routed"
	} else {
		if err := e.route.BlockIPv6(p.TunIface); err != nil {
			rollback()
			e.fail(err)
			return err
		}
		undo = append(undo, func() { _ = e.route.RestoreIPv6() })
		e.ipv6 = "blocked"
	}

	e.applied = true
	e.killMode = p.KillSwitch
	e.dnsMode = p.DNSMode
	e.lastErr = ""
	return nil
}

// Clear removes everything Apply installed. It is idempotent.
func (e *osEnforcer) Clear() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clearLocked()
}

// clearLocked undoes in reverse order and reports every failure, so a
// partial cleanup is never silently swallowed.
func (e *osEnforcer) clearLocked() error {
	var problems []string

	if e.ipv6 == "blocked" {
		if err := e.route.RestoreIPv6(); err != nil {
			problems = append(problems, "ipv6 restore: "+err.Error())
		}
	}
	if e.dnsMgr != nil {
		if err := e.dnsMgr.Restore(); err != nil {
			problems = append(problems, "dns restore: "+err.Error())
		}
	}
	if err := e.kill.Disable(); err != nil {
		problems = append(problems, "kill switch: "+err.Error())
	}

	e.applied = false
	e.killMode = ""
	e.dnsMode = ""
	e.ipv6 = "unknown"
	if len(problems) > 0 {
		err := fmt.Errorf("enforcement cleanup: %s", strings.Join(problems, "; "))
		e.lastErr = err.Error()
		return err
	}
	e.lastErr = ""
	return nil
}

// FailClosed re-asserts the block policy after unexpected tunnel loss.
func (e *osEnforcer) FailClosed(reason string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.applied {
		return fmt.Errorf("enforcement not active")
	}
	if err := e.kill.FailClosed(reason); err != nil {
		e.lastErr = err.Error()
		return err
	}
	return nil
}

// Status reports what the OS actually has applied.
func (e *osEnforcer) Status() app.EnforceStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := app.EnforceStatus{
		Available:         true,
		Applied:           e.applied,
		KillSwitch:        e.killMode,
		DNSMode:           e.dnsMode,
		IPv6:              e.ipv6,
		KillSwitchBackend: e.kill.BackendName(),
		DNSBackend:        e.dnsBackend,
		RoutingBackend:    e.route.BackendName(),
		Error:             e.lastErr,
	}
	if !e.applied && st.KillSwitch == "" {
		st.KillSwitch = string(firewall.OFF)
	}
	return st
}

func (e *osEnforcer) fail(err error) { e.lastErr = err.Error() }
