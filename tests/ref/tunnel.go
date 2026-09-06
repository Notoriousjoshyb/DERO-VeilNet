// Package ref is test-owned executable specification for the DERO // VEILNET
// contract. It is NOT production code: it provides minimal in-memory
// reference implementations of the binding Contract surfaces
// (internal/tunnel Engine, internal/events bus, token fields, node metadata,
// config paths) so conformance tests in tests/* run green without depending
// on sibling agents' half-finished trees. The same tests are written against
// the exact Contract symbol names and can be re-wired to the real packages
// once they land, without editing the assertions.
package ref

import (
	"errors"
	"sync"
	"time"
)

// State mirrors the Contract tunnel state enum.
type State string

const (
	Down       State = "DOWN"
	Connecting State = "CONNECTING"
	Up         State = "UP"
	Failed     State = "FAILED"
)

// Peer mirrors the Contract WireGuard peer descriptor.
type Peer struct {
	PublicKey string
	Endpoint  string
	AllowedIPs []string
	Keepalive int
}

// WireGuardConfig mirrors the Contract tunnel configuration.
type WireGuardConfig struct {
	PrivateKey string
	Addresses  []string
	DNS        []string
	Peers      []Peer
}

// Status mirrors the Contract tunnel status.
type Status struct {
	State         State
	Since         time.Time
	Endpoint      string
	LastHandshake time.Time
}

// Stats mirrors the Contract tunnel statistics.
type Stats struct {
	RxBytes       uint64
	TxBytes       uint64
	LastHandshake time.Time
}

// Engine mirrors the Contract TunnelEngine interface exactly.
type Engine interface {
	Start(cfg WireGuardConfig) error
	Stop() error
	Status() Status
	Statistics() Stats
	ApplyConfiguration(cfg WireGuardConfig) error
	RotateEndpoint(endpoint string) error
}

// FakeEngine is an in-memory Engine. Transitions: DOWN --Start--> CONNECTING
// --Handshake()--> UP; Stop() --> DOWN from any state. ApplyConfiguration
// while UP re-keys in place. RotateEndpoint swaps the active endpoint.
// It records every transition for assertion.
type FakeEngine struct {
	mu          sync.Mutex
	status      Status
	stats       Stats
	cfg         WireGuardConfig
	transitions []State
	handshakes  int
	failNext    bool
}

// NewFakeEngine returns a DOWN engine.
func NewFakeEngine() *FakeEngine {
	return &FakeEngine{status: Status{State: Down, Since: time.Now().UTC()}}
}

func validateConfig(cfg WireGuardConfig) error {
	if cfg.PrivateKey == "" {
		return errors.New("ref: private key required")
	}
	if len(cfg.Addresses) == 0 {
		return errors.New("ref: at least one tunnel address required")
	}
	if len(cfg.Peers) == 0 {
		return errors.New("ref: at least one peer required")
	}
	for _, p := range cfg.Peers {
		if p.PublicKey == "" || p.Endpoint == "" {
			return errors.New("ref: peer public key and endpoint required")
		}
		if len(p.AllowedIPs) == 0 {
			return errors.New("ref: peer AllowedIPs required")
		}
	}
	return nil
}

func (f *FakeEngine) setState(s State) {
	if f.status.State != s {
		f.transitions = append(f.transitions, s)
		f.status.State = s
		f.status.Since = time.Now().UTC()
	}
}

// Start brings the engine to CONNECTING. Synchronous for test determinism;
// the caller drives Handshake to reach UP, mirroring async WireGuard setup.
func (f *FakeEngine) Start(cfg WireGuardConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status.State == Connecting || f.status.State == Up {
		return errors.New("ref: engine already running")
	}
	if err := validateConfig(cfg); err != nil {
		f.setState(Failed)
		return err
	}
	f.cfg = cfg
	f.status.Endpoint = cfg.Peers[0].Endpoint
	if f.failNext {
		f.failNext = false
		f.setState(Failed)
		return errors.New("ref: injected start failure")
	}
	f.setState(Connecting)
	return nil
}

// Handshake simulates a completed WireGuard handshake, moving to UP.
func (f *FakeEngine) Handshake() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status.State != Connecting && f.status.State != Up {
		return
	}
	now := time.Now().UTC()
	f.handshakes++
	f.stats.LastHandshake = now
	f.status.LastHandshake = now
	f.setState(Up)
}

// InjectFailure makes the next Start fail (reconnect-path testing).
func (f *FakeEngine) InjectFailure() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext = true
}

// AddTraffic accumulates byte counters.
func (f *FakeEngine) AddTraffic(rx, tx uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stats.RxBytes += rx
	f.stats.TxBytes += tx
}

// Stop halts the engine from any state.
func (f *FakeEngine) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status.State == Down {
		return errors.New("ref: engine already stopped")
	}
	f.setState(Down)
	f.status.Endpoint = ""
	return nil
}

// Status returns a snapshot.
func (f *FakeEngine) Status() Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

// Statistics returns a snapshot.
func (f *FakeEngine) Statistics() Stats {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats
}

// ApplyConfiguration re-keys in place; allowed from CONNECTING or UP.
func (f *FakeEngine) ApplyConfiguration(cfg WireGuardConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status.State != Connecting && f.status.State != Up {
		return errors.New("ref: engine not running")
	}
	if err := validateConfig(cfg); err != nil {
		f.setState(Failed)
		return err
	}
	f.cfg = cfg
	f.status.Endpoint = cfg.Peers[0].Endpoint
	return nil
}

// RotateEndpoint swaps the active endpoint without full restart.
func (f *FakeEngine) RotateEndpoint(endpoint string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.status.State != Up {
		return errors.New("ref: rotate requires UP tunnel")
	}
	if endpoint == "" {
		return errors.New("ref: endpoint required")
	}
	found := false
	for _, p := range f.cfg.Peers {
		if p.Endpoint == endpoint {
			found = true
			break
		}
	}
	if !found {
		return errors.New("ref: unknown endpoint")
	}
	f.status.Endpoint = endpoint
	return nil
}

// Transitions returns the observed state sequence.
func (f *FakeEngine) Transitions() []State {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]State, len(f.transitions))
	copy(out, f.transitions)
	return out
}

// HandshakeCount reports completed handshakes.
func (f *FakeEngine) HandshakeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.handshakes
}
