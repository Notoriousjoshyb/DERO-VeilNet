// Package dns manages VeilNet DNS via per-OS backends (netsh + NRPT on
// Windows, systemd-resolved with /etc/resolv.conf fallback on Linux,
// networksetup with scutil fallback on macOS) with leak reporting.
//
// Modes: VEILNET / CUSTOM / DOH / SYSTEM-explicit-only.
//   - VEILNET: node-pushed resolvers via interface DNS + OS catch-all.
//   - CUSTOM: user resolvers, same mechanism.
//   - DOH: DNS-over-HTTPS templates registered before use (Windows 11).
//     Unknown servers are rejected rather than silently downgraded; OSes
//     without DoH registration return an explicit error.
//   - SYSTEM: explicit user opt-out only; restores OS resolvers and records
//     the choice. LeakState reports Leaking=true in this mode by design.
//
// Previous resolvers persist to a snapshot file so Apply/Restore never lose
// the user's original configuration (never brick). Contract event published:
// DNS_CHANGED.
package dns

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

// Mode is the DNS mode (binding contract names).
type Mode string

// DNS modes.
const (
	VEILNET Mode = "VEILNET"
	CUSTOM  Mode = "CUSTOM"
	DOH     Mode = "DOH"
	SYSTEM  Mode = "SYSTEM"
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

// sentinelName records pre-VeilNet resolvers for restore.
const sentinelName = "dns.json"

// snapshot is the crash-recovery + restore record.
type snapshot struct {
	Iface     string   `json:"iface"`
	Servers   []string `json:"servers"`
	Mode      Mode     `json:"mode"`
	NRPTNames []string `json:"nrpt_names"`
}

// LeakState reports the effective DNS posture.
type LeakState struct {
	// Resolvers are the currently effective resolver IPs.
	Resolvers []string `json:"resolvers"`
	// Route is "tunnel" when every resolver is tunnel-scoped, "system"
	// otherwise, "unknown" when it cannot be determined.
	Route string `json:"route"`
	// Leaking is true when a non-tunnel resolver is effective.
	Leaking bool `json:"leaking"`
}

// Manager owns DNS application/restore for one interface.
type Manager struct {
	runner   Runner
	backend  Backend
	stateDir string
	iface    string
	mode     Mode
	servers  []string
}

// Option wires a Manager.
type Option func(*Manager)

// WithStateDir overrides the platform state dir for the snapshot
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

// New builds a Manager for iface.
func New(runner Runner, iface string, opts ...Option) *Manager {
	m := &Manager{runner: runner, backend: selectBackend(), iface: iface, mode: SYSTEM}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Mode returns the active mode.
func (m *Manager) Mode() Mode { return m.mode }

// Servers returns the active tunnel resolvers (empty for SYSTEM).
func (m *Manager) Servers() []string { return append([]string(nil), m.servers...) }

// BackendName reports the active OS backend (diagnostics).
func (m *Manager) BackendName() string { return m.backend.Name() }

// Apply sets resolvers for mode on the interface:
//   - VEILNET/CUSTOM use servers (must be non-empty).
//   - DOH uses servers, each requiring a known DoH template.
//   - SYSTEM ignores servers and restores OS resolvers explicitly.
func (m *Manager) Apply(mode Mode, servers []string) error {
	switch mode {
	case VEILNET, CUSTOM:
		if len(servers) == 0 {
			return fmt.Errorf("dns: %s requires at least one resolver", mode)
		}
		m.ensureSnapshot()
		if err := m.backend.Set(m.runner, m.iface, servers); err != nil {
			return err
		}
	case DOH:
		if len(servers) == 0 {
			return fmt.Errorf("dns: DOH requires at least one resolver")
		}
		for _, s := range servers {
			if _, ok := dohTemplates[s]; !ok {
				return fmt.Errorf("dns: no known DoH template for %s (refusing silent downgrade)", s)
			}
		}
		m.ensureSnapshot()
		if err := m.backend.RegisterDOH(m.runner, servers); err != nil {
			return err
		}
		if err := m.backend.Set(m.runner, m.iface, servers); err != nil {
			return err
		}
	case SYSTEM:
		if err := m.Restore(); err != nil {
			return err
		}
		m.mode = SYSTEM
		m.servers = nil
		events.Publish(events.DNS_CHANGED, map[string]any{"mode": string(SYSTEM)})
		return nil
	default:
		return fmt.Errorf("dns: unknown mode %q", mode)
	}
	m.mode = mode
	m.servers = append([]string(nil), servers...)
	events.Publish(events.DNS_CHANGED, map[string]any{"mode": string(mode), "servers": servers})
	return nil
}

// Restore removes VeilNet DNS state and reinstates the snapshotted OS
// resolvers. Idempotent.
func (m *Manager) Restore() error {
	s := m.readSnapshot()
	first := m.backend.Restore(m.runner, m.iface, s.Servers)
	for _, p := range m.snapshotPaths() {
		_ = os.Remove(p)
	}
	m.mode = SYSTEM
	m.servers = nil
	return first
}

// LeakState queries effective resolvers and compares against tunnel servers.
func (m *Manager) LeakState() LeakState {
	got := m.backend.Effective(m.runner, m.iface)
	st := LeakState{Resolvers: got, Route: "unknown"}
	if len(got) == 0 {
		return st
	}
	if m.mode == SYSTEM {
		st.Route = "system"
		st.Leaking = true
		return st
	}
	allowed := map[string]bool{}
	for _, s := range m.servers {
		allowed[s] = true
	}
	st.Route = "tunnel"
	for _, r := range got {
		if !allowed[r] {
			st.Route = "system"
			st.Leaking = true
			break
		}
	}
	return st
}

func (m *Manager) ensureSnapshot() {
	for _, p := range m.snapshotPaths() {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return
		}
	}
	servers := m.backend.Current(m.runner, m.iface)
	m.writeSnapshot(snapshot{Iface: m.iface, Servers: servers, Mode: m.mode, NRPTNames: []string{nrptCatchAll}})
}

func isIP(s string) bool {
	var b [4]byte
	n, ok := parseIPv4(s, &b)
	return ok && n == 4
}

func parseIPv4(s string, b *[4]byte) (int, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return 0, false
	}
	for i, p := range parts {
		var v int
		if len(p) == 0 || len(p) > 3 {
			return 0, false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return 0, false
			}
			v = v*10 + int(c-'0')
		}
		if v > 255 {
			return 0, false
		}
		b[i] = byte(v)
	}
	return 4, true
}

func (m *Manager) snapshotPath() string {
	paths := m.snapshotPaths()
	if len(paths) == 0 {
		return ""
	}
	return paths[0]
}

// snapshotPaths lists the write-primary snapshot first, then the legacy
// ~/.veilnet location kept for migration (read + cleanup only).
func (m *Manager) snapshotPaths() []string {
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

func (m *Manager) writeSnapshot(s snapshot) {
	p := m.snapshotPath()
	if p == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	raw, _ := json.Marshal(s)
	_ = os.WriteFile(p, raw, 0o600)
}

func (m *Manager) readSnapshot() snapshot {
	var zero snapshot
	for _, p := range m.snapshotPaths() {
		if p == "" {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var s snapshot
		if err := json.Unmarshal(raw, &s); err == nil {
			return s
		}
	}
	return zero
}
