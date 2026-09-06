// Package tunnel implements the VeilNet TunnelEngine contract.
//
// The engine drives a real WireGuard data plane: either a kernel-managed
// interface (WireGuardNT / wintun interface configured via wgctrl) or an
// embedded wireguard-go userspace device. State is always derived from the
// live device (config applied, handshake timestamps, byte counters) — the
// engine never reports UP without a real device behind it.
//
// Backend selection on Start:
//  1. If an interface named IfaceName already exists (created by the
//     WireGuardNT service path, see docs/WINDOWS_NETWORKING.md), it is
//     configured via wgctrl.
//  2. Otherwise an embedded userspace device is created over a TUN from
//     TUNFactory (production: tun.CreateTUN backed by Wintun; tests inject
//     an in-memory TUN).
//
// Contract events published: TUNNEL_STARTED, TUNNEL_STOPPED, CIRCUIT_ROTATED,
// ERROR.
package tunnel

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dero-veilnet/veilnet/internal/events"
	vwg "github.com/dero-veilnet/veilnet/internal/wireguard"
)

// State is the tunnel lifecycle state.
type State string

// Binding contract states.
const (
	DOWN       State = "DOWN"
	CONNECTING State = "CONNECTING"
	UP         State = "UP"
	FAILED     State = "FAILED"
)

// Peer is one WireGuard peer of the tunnel.
type Peer struct {
	PublicKey  string
	Endpoint   string
	AllowedIPs []string
	Keepalive  int
}

// WireGuardConfig is the tunnel configuration (binding contract).
type WireGuardConfig struct {
	PrivateKey string
	Addresses  []string
	DNS        []string
	Peers      []Peer
}

// Status is a point-in-time tunnel snapshot (binding contract).
type Status struct {
	State         State
	Since         time.Time
	Endpoint      string
	LastHandshake time.Time
	// Detail names the active data-plane backend: "kernel (...)" or
	// "userspace (...)". Always set after Start; empty before.
	Detail string
}

// Stats holds monotonic tunnel counters (binding contract).
type Stats struct {
	RxBytes       uint64
	TxBytes       uint64
	LastHandshake time.Time
}

// Engine is the binding TunnelEngine interface.
type Engine interface {
	Start(cfg WireGuardConfig) error
	Stop() error
	Status() Status
	Statistics() Stats
	ApplyConfiguration(cfg WireGuardConfig) error
	RotateEndpoint(endpoint string) error
}

// TunnelEngine is an alias kept for callers using the Contract doc name.
type TunnelEngine = Engine

// IfaceName is the preferred OS interface name for the kernel path.
const IfaceName = "veilnet"

// Option customizes engine construction. The zero engine uses production
// defaults (OS TUN, default UDP bind, 5s watchdog poll).
type Option func(*engine)

// WithInterfaceName overrides the kernel-path interface name.
func WithInterfaceName(name string) Option {
	return func(e *engine) { e.iface = name }
}

// WithListenPort pins the userspace UDP listen port (0 = ephemeral).
// The contract config carries no port, so this is engine-local wiring.
func WithListenPort(port int) Option {
	return func(e *engine) { e.listenPort = port }
}

// WithTUNFactory injects TUN creation (tests supply in-memory TUNs).
func WithTUNFactory(f TUNFactory) Option {
	return func(e *engine) { e.newTUN = f }
}

// WithBindFactory injects UDP bind creation.
func WithBindFactory(f BindFactory) Option {
	return func(e *engine) { e.newBind = f }
}

// WithPollInterval overrides the watchdog poll interval.
func WithPollInterval(d time.Duration) Option {
	return func(e *engine) { e.pollInterval = d }
}

// WithStaleAfter overrides how old a handshake may be before recovery.
func WithStaleAfter(d time.Duration) Option {
	return func(e *engine) { e.staleAfter = d }
}

// WithMaxRetries caps consecutive failed recoveries before FAILED.
func WithMaxRetries(n int) Option {
	return func(e *engine) { e.maxRetries = n }
}

// OnWake is called when the power poll hook detects a sleep/wake cycle.
// The service layer may also invoke Engine.Wake directly on
// WM_POWERBROADCAST/PBT_APMRESUME.
type OnWake func()

// WithOnWake registers the wake hook.
func WithOnWake(h OnWake) Option {
	return func(e *engine) { e.onWake = h }
}

// New builds an Engine. Extra options beyond the contract are construction
// wiring only; the Engine interface itself matches the Contract exactly.
func New(opts ...Option) Engine {
	e := &engine{
		iface:        IfaceName,
		state:        DOWN,
		since:        time.Now(),
		newTUN:       defaultTUNFactory,
		newBind:      defaultBindFactory,
		pollInterval: 5 * time.Second,
		staleAfter:   3 * time.Minute,
		maxRetries:   5,
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

type engine struct {
	mu           sync.RWMutex
	state        State
	since        time.Time
	cfg          WireGuardConfig
	endpoint     string
	lastHS       time.Time
	rx, tx       uint64
	iface        string
	listenPort   int
	newTUN       TUNFactory
	newBind      BindFactory
	pollInterval time.Duration
	staleAfter   time.Duration
	maxRetries   int
	onWake       OnWake

	backend backend
	cancel  contextCancel
	wg      sync.WaitGroup
	retries int
	// backendKind/backendDetail record the Start selection for
	// Status().Detail (single writer: createBackend).
	backendKind   BackendKind
	backendDetail string
}

type contextCancel = func()

// Start validates cfg, brings up the data plane and starts the watchdog.
// It returns an error (state FAILED) when no backend can be created —
// for example without admin rights on Windows. It never reports UP
// without a live device.
func (e *engine) Start(cfg WireGuardConfig) error {
	wcfg := toWireguard(cfg, 0)
	if err := vwg.Validate(wcfg); err != nil {
		return err
	}

	e.mu.Lock()
	if e.backend != nil {
		e.mu.Unlock()
		return errors.New("tunnel: already started")
	}
	e.cfg = cfg
	if len(cfg.Peers) > 0 {
		e.endpoint = cfg.Peers[0].Endpoint
	}
	e.setLocked(CONNECTING, time.Now())
	e.retries = 0
	e.mu.Unlock()

	be, err := e.createBackend(cfg)
	if err != nil {
		e.fail(err)
		return err
	}

	e.mu.Lock()
	e.backend = be
	e.mu.Unlock()

	stop := make(chan struct{})
	var once sync.Once
	e.mu.Lock()
	e.cancel = func() { once.Do(func() { close(stop) }) }
	e.mu.Unlock()
	e.wg.Add(1)
	go e.watchdogLoop(stop)

	rx, tx, hs, perr := be.probe()
	e.mu.Lock()
	if perr == nil {
		if rx > e.rx {
			e.rx = rx
		}
		if tx > e.tx {
			e.tx = tx
		}
		if !hs.IsZero() {
			e.lastHS = hs
			e.setLocked(UP, e.since)
		}
	}
	e.mu.Unlock()

	events.Publish(events.TUNNEL_STARTED, map[string]any{"endpoint": e.Endpoint()})
	return nil
}

// Endpoint returns the primary peer endpoint (for event payloads).
func (e *engine) Endpoint() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.endpoint
}

// Stop tears down the device and watchdog. It is idempotent.
func (e *engine) Stop() error {
	e.mu.Lock()
	cancel := e.cancel
	be := e.backend
	e.cancel = nil
	e.backend = nil
	e.setLocked(DOWN, time.Now())
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	e.wg.Wait()
	var err error
	if be != nil {
		err = be.close()
	}
	events.Publish(events.TUNNEL_STOPPED, nil)
	return err
}

// Status returns the current tunnel snapshot.
func (e *engine) Status() Status {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rep := backendReport{kind: e.backendKind, detail: e.backendDetail}
	if rep.kind == "" {
		return Status{State: e.state, Since: e.since, Endpoint: e.endpoint, LastHandshake: e.lastHS}
	}
	return Status{State: e.state, Since: e.since, Endpoint: e.endpoint, LastHandshake: e.lastHS, Detail: rep.String()}
}

// Statistics returns monotonic counters scraped from the live device.
func (e *engine) Statistics() Stats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return Stats{RxBytes: e.rx, TxBytes: e.tx, LastHandshake: e.lastHS}
}

// ApplyConfiguration replaces the running config (peers/endpoints/DNS
// addresses are re-applied; the device is re-keyed as needed).
func (e *engine) ApplyConfiguration(cfg WireGuardConfig) error {
	wcfg := toWireguard(cfg, 0)
	if err := vwg.Validate(wcfg); err != nil {
		return err
	}
	e.mu.RLock()
	be := e.backend
	e.mu.RUnlock()
	if be == nil {
		return errors.New("tunnel: not started")
	}
	if err := be.apply(cfg); err != nil {
		return err
	}
	e.mu.Lock()
	e.cfg = cfg
	if len(cfg.Peers) > 0 {
		e.endpoint = cfg.Peers[0].Endpoint
	}
	e.retries = 0
	e.mu.Unlock()
	return nil
}

// RotateEndpoint switches the primary peer to endpoint, rebinds the UDP
// socket (NAT traversal refresh) and resets the recovery backoff.
func (e *engine) RotateEndpoint(endpoint string) error {
	if endpoint == "" {
		return errors.New("tunnel: empty endpoint")
	}
	e.mu.RLock()
	be := e.backend
	cfg := e.cfg
	e.mu.RUnlock()
	if be == nil {
		return errors.New("tunnel: not started")
	}
	if len(cfg.Peers) == 0 {
		return errors.New("tunnel: no peers to rotate")
	}
	cfg.Peers[0].Endpoint = endpoint
	if err := be.apply(cfg); err != nil {
		return err
	}
	if err := be.rebind(); err != nil {
		return fmt.Errorf("tunnel: rebind: %w", err)
	}
	e.mu.Lock()
	e.cfg = cfg
	e.endpoint = endpoint
	e.retries = 0
	if e.state == FAILED {
		e.setLocked(CONNECTING, time.Now())
	}
	e.mu.Unlock()
	events.Publish(events.CIRCUIT_ROTATED, map[string]any{"endpoint": endpoint})
	return nil
}

// Wake forces a rebind + immediate re-probe after system sleep.
// The watchdog also detects sleep via wall-clock jumps (poll hook), so this
// is an accelerator for platforms that deliver power notifications.
func (e *engine) Wake() {
	e.mu.RLock()
	be := e.backend
	e.mu.RUnlock()
	if be == nil {
		return
	}
	_ = be.rebind()
	e.mu.Lock()
	e.retries = 0
	e.mu.Unlock()
	if h := e.onWake; h != nil {
		h()
	}
}

func (e *engine) setLocked(s State, t time.Time) {
	e.state = s
	e.since = t
}

func (e *engine) fail(err error) {
	e.mu.Lock()
	e.setLocked(FAILED, time.Now())
	e.mu.Unlock()
	events.Publish(events.ERROR, map[string]any{"op": "tunnel", "error": err.Error()})
}

func toWireguard(cfg WireGuardConfig, listenPort int) vwg.Config {
	out := vwg.Config{
		PrivateKey: cfg.PrivateKey,
		ListenPort: listenPort,
		Addresses:  append([]string(nil), cfg.Addresses...),
		DNS:        append([]string(nil), cfg.DNS...),
	}
	for _, p := range cfg.Peers {
		out.Peers = append(out.Peers, vwg.Peer{
			PublicKey:  p.PublicKey,
			Endpoint:   p.Endpoint,
			AllowedIPs: append([]string(nil), p.AllowedIPs...),
			Keepalive:  p.Keepalive,
		})
	}
	return out
}

func fromWireguard(cfg vwg.Config) WireGuardConfig {
	out := WireGuardConfig{
		PrivateKey: cfg.PrivateKey,
		Addresses:  append([]string(nil), cfg.Addresses...),
		DNS:        append([]string(nil), cfg.DNS...),
	}
	for _, p := range cfg.Peers {
		out.Peers = append(out.Peers, Peer{
			PublicKey:  p.PublicKey,
			Endpoint:   p.Endpoint,
			AllowedIPs: append([]string(nil), p.AllowedIPs...),
			Keepalive:  p.Keepalive,
		})
	}
	return out
}
