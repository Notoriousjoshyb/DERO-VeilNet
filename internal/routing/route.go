// Package routing manages secure OS routes for VeilNet tunnels via
// per-OS backends (netsh on Windows, `ip route` on Linux, BSD `route`
// on macOS). IPv6 is blocked at the firewall plus tunnel-interface
// hardening unless explicitly routed — never silently leaked.
//
// All OS mutation goes through Runner so tests use a fake and assert exact
// commands. Added routes persist to a state file so a crashed run can be
// cleaned on next start (never brick, never accumulate).
package routing

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/dero-veilnet/veilnet/internal/platform"
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

// Route records one route added by the manager (for exact removal).
type Route struct {
	Dest    string `json:"dest"`
	Gateway string `json:"gateway"`
	Iface   string `json:"iface"`
	Metric  int    `json:"metric"`
}

// stateFileName persists added routes for crash recovery.
const stateFileName = "routes.json"

// Manager applies and removes tunnel routes.
type Manager struct {
	runner   Runner
	backend  Backend
	stateDir string
	added    []Route
	metric   map[string]int // iface -> previous metric (restore)
	ipv6Off  bool
}

// Option wires a Manager.
type Option func(*Manager)

// WithStateDir overrides the platform state dir for route state
// (tests/services).
func WithStateDir(dir string) Option {
	return func(m *Manager) { m.stateDir = dir }
}

// WithBackend overrides the OS-selected backend (tests).
func WithBackend(be Backend) Option {
	return func(m *Manager) {
		if be != nil {
			m.backend = be
		}
	}
}

// New builds a Manager and reconciles stale state from a crashed run.
func New(runner Runner, opts ...Option) *Manager {
	m := &Manager{runner: runner, backend: selectBackend(), metric: map[string]int{}}
	for _, o := range opts {
		o(m)
	}
	m.recover()
	return m
}

// BackendName reports the active OS backend (diagnostics).
func (m *Manager) BackendName() string { return m.backend.Name() }

func (m *Manager) statePath() string {
	paths := m.statePaths()
	if len(paths) == 0 {
		return ""
	}
	return paths[0]
}

// statePaths lists the write-primary state file first, then the legacy
// ~/.veilnet location kept for migration (read + cleanup only).
func (m *Manager) statePaths() []string {
	if m.stateDir != "" {
		return []string{filepath.Join(m.stateDir, stateFileName)}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	primary := filepath.Join(platform.AppDirs().State, stateFileName)
	legacy := filepath.Join(home, ".veilnet", stateFileName)
	if primary == legacy {
		return []string{primary}
	}
	return []string{primary, legacy}
}

func (m *Manager) save() {
	p := m.statePath()
	if p == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	raw, _ := json.Marshal(map[string]any{"routes": m.added})
	_ = os.WriteFile(p, raw, 0o600)
}

func (m *Manager) recover() {
	var raw []byte
	for _, p := range m.statePaths() {
		if p == "" {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		raw = b
		break
	}
	if raw == nil {
		return
	}
	var st struct {
		Routes []Route `json:"routes"`
	}
	if json.Unmarshal(raw, &st) != nil {
		return
	}
	// Best-effort removal of stale routes from a crashed run.
	for _, r := range st.Routes {
		_ = m.deleteRoute(r)
	}
	for _, p := range m.statePaths() {
		_ = os.Remove(p)
	}
}

// EnsureDefaultViaTunnel routes all IPv4 through the tunnel gateway.
// tunGateway is the tunnel-side next hop (typically the peer's tunnel IP);
// iface is the OS interface name.
func (m *Manager) EnsureDefaultViaTunnel(iface, tunGateway string, metric int) error {
	r := Route{Dest: "0.0.0.0/0", Gateway: tunGateway, Iface: iface, Metric: metric}
	if err := m.addRoute(r); err != nil {
		return err
	}
	m.added = append(m.added, r)
	m.save()
	return nil
}

// EnsurePeerBypass pins the handshake endpoint to the original gateway so
// the encrypted session survives the default-route switch.
func (m *Manager) EnsurePeerBypass(peerIP, origIface, origGateway string, metric int) error {
	r := Route{Dest: peerIP + "/32", Gateway: origGateway, Iface: origIface, Metric: metric}
	if err := m.addRoute(r); err != nil {
		return err
	}
	m.added = append(m.added, r)
	m.save()
	return nil
}

// SetInterfaceMetric lowers/raises the tunnel interface metric and records
// the previous value for restore.
func (m *Manager) SetInterfaceMetric(iface string, metric int) error {
	prev, err := m.getMetric(iface)
	if err == nil {
		if _, seen := m.metric[iface]; !seen {
			m.metric[iface] = prev
		}
	}
	return m.setMetric(iface, metric)
}

// RemoveAll deletes every route added by this manager (reverse order).
func (m *Manager) RemoveAll() error {
	var first error
	for i := len(m.added) - 1; i >= 0; i-- {
		if err := m.deleteRoute(m.added[i]); err != nil && first == nil {
			first = err
		}
	}
	m.added = nil
	for iface, prev := range m.metric {
		if err := m.setMetric(iface, prev); err != nil && first == nil {
			first = err
		}
	}
	m.metric = map[string]int{}
	if m.ipv6Off {
		if err := m.restoreIPv6(); err != nil && first == nil {
			first = err
		}
	}
	for _, p := range m.statePaths() {
		_ = os.Remove(p)
	}
	return first
}

// Added returns currently tracked routes (for tests/diagnostics).
func (m *Manager) Added() []Route {
	return append([]Route(nil), m.added...)
}

// ---------------------------------------------------------------------------
// backend delegation (no OS branches here)
// ---------------------------------------------------------------------------

func (m *Manager) addRoute(r Route) error {
	return m.backend.Add(m.runner, r)
}

func (m *Manager) deleteRoute(r Route) error {
	return m.backend.Delete(m.runner, r)
}

func (m *Manager) setMetric(iface string, metric int) error {
	return m.backend.SetMetric(m.runner, iface, metric)
}

func (m *Manager) getMetric(iface string) (int, error) {
	return m.backend.GetMetric(m.runner, iface)
}

// BlockIPv6 blocks IPv6 egress at the firewall and disables autoconfiguration
// on the tunnel interface. Call RemoveAll (or RestoreIPv6) to reverse.
func (m *Manager) BlockIPv6(tunnelIface string) error {
	if err := m.backend.BlockIPv6(m.runner, tunnelIface); err != nil {
		return err
	}
	m.ipv6Off = true
	return nil
}

// RestoreIPv6 reverses BlockIPv6.
func (m *Manager) RestoreIPv6() error {
	return m.restoreIPv6()
}

func (m *Manager) restoreIPv6() error {
	err := m.backend.RestoreIPv6(m.runner)
	m.ipv6Off = false
	return err
}
