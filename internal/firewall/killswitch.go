// Package firewall enforces the VeilNet kill switch via per-OS backends:
// `netsh advfirewall` on Windows, nftables (iptables fallback) on Linux,
// pf anchors on macOS.
//
// Modes: OFF / ON_WHILE_CONNECTED / ALWAYS_ON.
//
// Design (allow-list, every backend):
//   - The outbound default is switched to deny and a small set of named
//     allow rules is added: handshake endpoint (UDP), tunnel-local traffic,
//     DHCP, optional LAN. Everything else drops.
//   - On unexpected tunnel loss the rules STAY (fail-closed); only an
//     explicit Disable removes rules and restores the previous policy.
//   - A sentinel file records applied rules + previous policy, so a crashed
//     run is reconciled on the next Enable (stale rules removed first).
//     The manager never changes global defaults without recording the
//     previous value, and always restores it (never brick).
//
// Contract event published: KILL_SWITCH_ENABLED.
package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/dero-veilnet/veilnet/internal/events"
	"github.com/dero-veilnet/veilnet/internal/platform"
)

// Mode is the kill-switch mode (binding contract names).
type Mode string

// Kill-switch modes.
const (
	OFF                Mode = "OFF"
	ON_WHILE_CONNECTED Mode = "ON_WHILE_CONNECTED"
	ALWAYS_ON          Mode = "ALWAYS_ON"
)

// Runner executes one OS command and returns combined output.
type Runner interface {
	Run(name string, args ...string) (string, error)
}

// ExecRunner runs real OS commands with a timeout.
type ExecRunner struct {
	Timeout time.Duration
}

// Run executes name args and returns combined output.
func (r ExecRunner) Run(name string, args ...string) (string, error) {
	to := r.Timeout
	if to <= 0 {
		to = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// sentinelName records applied state for crash recovery.
const sentinelName = "killswitch.json"

// sentinel is the crash-recovery record.
type sentinel struct {
	Rules    []string `json:"rules"`
	Policy   string   `json:"policy"`
	Endpoint string   `json:"endpoint"`
	Mode     Mode     `json:"mode"`
}

// Manager owns the kill-switch rules.
type Manager struct {
	runner     Runner
	backend    Backend
	stateDir   string
	lanAllowed bool
	mode       Mode
	active     bool
}

// Option wires a Manager.
type Option func(*Manager)

// WithStateDir overrides the platform state dir for the sentinel
// (tests/services).
func WithStateDir(dir string) Option {
	return func(m *Manager) { m.stateDir = dir }
}

// WithLANAllowed permits direct LAN traffic (printers, NAS) with the
// kill switch engaged. Default denies LAN (strictest).
func WithLANAllowed(allow bool) Option {
	return func(m *Manager) { m.lanAllowed = allow }
}

// WithBackend overrides the OS-selected backend (tests).
func WithBackend(be Backend) Option {
	return func(m *Manager) {
		if be != nil {
			m.backend = be
		}
	}
}

// New builds an idle Manager.
func New(runner Runner, opts ...Option) *Manager {
	m := &Manager{runner: runner, backend: selectBackend()}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Mode returns the last enabled mode (OFF when idle).
func (m *Manager) Mode() Mode {
	if !m.active {
		return OFF
	}
	return m.mode
}

// Active reports whether kill-switch rules are currently applied.
func (m *Manager) Active() bool { return m.active }

// BackendName reports the active OS backend (diagnostics).
func (m *Manager) BackendName() string { return m.backend.Name() }

func (m *Manager) sentinelPath() string {
	paths := m.sentinelPaths()
	if len(paths) == 0 {
		return ""
	}
	return paths[0]
}

// sentinelPaths lists the write-primary sentinel first, then the legacy
// ~/.veilnet location kept for migration (read + cleanup only).
func (m *Manager) sentinelPaths() []string {
	if m.stateDir != "" {
		return []string{filepath.Join(m.stateDir, sentinelName)}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	primary := filepath.Join(platform.AppDirs().State, sentinelName)
	legacy := filepath.Join(home, ".veilnet", sentinelName)
	if primary == legacy {
		return []string{primary}
	}
	return []string{primary, legacy}
}

// Enable applies the kill switch for mode with the given handshake endpoint
// (endpointIP:port of the WireGuard peer) and tunnel address (local TUN IP).
// Any stale rules from a crashed run are removed first.
func (m *Manager) Enable(mode Mode, endpointIP string, endpointPort int, tunAddr string) error {
	if mode == OFF {
		return m.Disable()
	}
	if strings.TrimSpace(endpointIP) == "" || endpointPort <= 0 || endpointPort > 65535 {
		return fmt.Errorf("firewall: bad handshake endpoint %s:%d", endpointIP, endpointPort)
	}
	if strings.TrimSpace(tunAddr) == "" {
		return fmt.Errorf("firewall: empty tunnel address")
	}

	// Crash recovery: a sentinel means the previous run never cleaned up.
	m.removeStale()

	policy, err := m.backend.CurrentPolicy(m.runner)
	if err != nil {
		return fmt.Errorf("firewall: snapshot policy: %w", err)
	}

	spec := Spec{EndpointIP: endpointIP, EndpointPort: endpointPort, TunAddr: tunAddr, LANAllowed: m.lanAllowed}
	if err := m.backend.Enable(m.runner, spec); err != nil {
		_ = m.backend.Remove(m.runner, m.backend.RuleNames(spec))
		return fmt.Errorf("firewall: apply rules: %w", err)
	}
	if err := m.backend.SetBlock(m.runner); err != nil {
		_ = m.backend.Remove(m.runner, m.backend.RuleNames(spec))
		return fmt.Errorf("firewall: block outbound: %w", err)
	}

	m.writeSentinel(sentinel{Rules: m.backend.RuleNames(spec), Policy: policy,
		Endpoint: fmt.Sprintf("%s:%d", endpointIP, endpointPort), Mode: mode})
	m.mode = mode
	m.active = true
	events.Publish(events.KILL_SWITCH_ENABLED, map[string]any{
		"mode": string(mode), "endpoint": fmt.Sprintf("%s:%d", endpointIP, endpointPort),
	})
	return nil
}

// FailClosed re-asserts the block policy after unexpected tunnel loss
// (TUNNEL FAILED / watchdog exhaustion). Rules stay in place; only an
// explicit Disable lifts them.
func (m *Manager) FailClosed(reason string) error {
	if !m.active {
		return fmt.Errorf("firewall: kill switch not active")
	}
	if err := m.backend.SetBlock(m.runner); err != nil {
		return err
	}
	events.Publish(events.KILL_SWITCH_ENABLED, map[string]any{
		"mode": string(m.mode), "failClosed": true, "reason": reason,
	})
	return nil
}

// Disable removes every rule this manager applied and restores the previous
// outbound policy. Idempotent: with no rules applied it only ensures the
// sentinel is gone.
func (m *Manager) Disable() error {
	s := m.readSentinel()
	if len(s.Rules) > 0 {
		_ = m.backend.Remove(m.runner, s.Rules)
	} else if m.active {
		// No sentinel (e.g. state dir moved): fall back to removing the
		// full known rule set (LAN superset covers both variants).
		_ = m.backend.Remove(m.runner, m.backend.RuleNames(Spec{LANAllowed: true}))
	}
	if s.Policy != "" {
		_ = m.backend.Restore(m.runner, s.Policy)
	}
	for _, p := range m.sentinelPaths() {
		_ = os.Remove(p)
	}
	m.active = false
	m.mode = OFF
	return nil
}

// Rules returns the currently applied rule names (diagnostics/tests).
func (m *Manager) Rules() []string {
	return m.readSentinel().Rules
}

// removeStale deletes rules recorded by a previous (crashed) run.
func (m *Manager) removeStale() {
	s := m.readSentinel()
	if len(s.Rules) == 0 {
		return
	}
	_ = m.backend.Remove(m.runner, s.Rules)
	for _, p := range m.sentinelPaths() {
		_ = os.Remove(p)
	}
}

func (m *Manager) writeSentinel(s sentinel) {
	p := m.sentinelPath()
	if p == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	raw, _ := json.Marshal(s)
	_ = os.WriteFile(p, raw, 0o600)
}

func (m *Manager) readSentinel() sentinel {
	var zero sentinel
	for _, p := range m.sentinelPaths() {
		if p == "" {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var s sentinel
		if err := json.Unmarshal(raw, &s); err == nil {
			return s
		}
	}
	return zero
}
