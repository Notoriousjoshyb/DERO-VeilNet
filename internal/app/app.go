// Package app is the client orchestrator: node select/connect/disconnect,
// latency probing, session timing, bandwidth stats, payment/session
// surface, auto-select scoring, 2-hop circuits, and privacy diagnostics.
//
// Engine and node-provider dependencies are local interfaces whose shapes
// match the binding Contract (internal/tunnel Engine, registry metadata).
// The privileged service injects the real tunnel engine; the GUI and CLI
// drive App directly or over IPC. No traffic content is ever logged.
package app

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/dero-veilnet/veilnet/internal/config"
	"github.com/dero-veilnet/veilnet/internal/events"
	"github.com/dero-veilnet/veilnet/internal/storage"
)

// Engine state enum (binding contract values).
const (
	StateDown       = "DOWN"
	StateConnecting = "CONNECTING"
	StateUp         = "UP"
	StateFailed     = "FAILED"
)

// Peer is one WireGuard peer (contract shape).
type Peer struct {
	PublicKey  string
	Endpoint   string
	AllowedIPs []string
	Keepalive  int
}

// WGConfig configures the tunnel engine (contract shape).
type WGConfig struct {
	PrivateKey string
	Addresses  []string
	DNS        []string
	Peers      []Peer
}

// EngineStatus mirrors the contract Status shape.
type EngineStatus struct {
	State         string
	Since         time.Time
	Endpoint      string
	LastHandshake time.Time
}

// EngineStats mirrors the contract Stats shape.
type EngineStats struct {
	RxBytes       int64
	TxBytes       int64
	LastHandshake time.Time
}

// Engine mirrors the binding TunnelEngine interface. The real
// implementation is injected by the service wiring.
type Engine interface {
	Start(cfg WGConfig) error
	Stop() error
	Status() EngineStatus
	Statistics() EngineStats
	ApplyConfiguration(cfg WGConfig) error
	RotateEndpoint(endpoint string) error
}

// NodeInfo mirrors registry node metadata plus live observations.
type NodeInfo struct {
	NodeID             string
	WGPubkey           string
	Region             string
	Country            string
	City               string
	Endpoint           string
	PricePerHourDero   float64
	CapacityMaxClients int
	ProtocolVersion    int
	BondDero           float64
	Status             string
	Version            string
	// Live observations (not registry metadata).
	Load      float64 // 0..1, clients/capacity when known
	LatencyMs int64   // last probe, -1 unknown
	Trust     float64 // local trust 0..1
	FailCount int     // consecutive local failures
}

// NodesProvider supplies candidate exit/entry nodes.
type NodesProvider interface {
	ListNodes() ([]NodeInfo, error)
}

// StaticNodes is a fixed in-memory provider (demo, tests, fallback).
type StaticNodes struct {
	mu    sync.RWMutex
	nodes []NodeInfo
}

// NewStaticNodes builds a provider over nodes.
func NewStaticNodes(nodes []NodeInfo) *StaticNodes {
	return &StaticNodes{nodes: append([]NodeInfo(nil), nodes...)}
}

// ListNodes returns a copy of the list.
func (p *StaticNodes) ListNodes() ([]NodeInfo, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]NodeInfo(nil), p.nodes...), nil
}

// Set replaces the list.
func (p *StaticNodes) Set(nodes []NodeInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nodes = append([]NodeInfo(nil), nodes...)
}

// SessionInfo surfaces current session authorization state.
type SessionInfo struct {
	Active    bool
	SessionID string
	NodeID    string
	StartedAt time.Time
	ExpiresAt time.Time
}

// PaymentInfo surfaces explicit-payment state. VeilNet never auto-spends.
type PaymentInfo struct {
	MaxPerHourDero float64
	SpentLastHour  float64
	Receipts       int
	LastTxID       string
	PendingApproval bool
}

// ConnState is the observable client state for UI/CLI.
type ConnState struct {
	EngineState string
	Node        *NodeInfo
	ConnectedAt time.Time
	ElapsedSecs int64
	RxBytes     int64
	TxBytes     int64
	Session     SessionInfo
	Payment     PaymentInfo
	Circuit     Circuit
	Demo        bool
}

// App orchestrates the client data path (via Engine) and control plane.
type App struct {
	mu       sync.RWMutex
	cfg      config.ClientConfig
	store    *storage.Store
	engine   Engine
	nodes    NodesProvider
	demo     bool
	node     *NodeInfo
	connID   int64
	sess     SessionInfo
	circuit  Circuit
	pendingApproval bool
	savePath string
	// Wallet connection for explicit payments (see wallet.go). nil
	// means wallet-less: demo and unpaid nodes still work.
	wallet      *walletConn
	walletState WalletStatus
	// enforcer applies kill switch / DNS / IPv6 protection to the OS.
	// nil in the unprivileged GUI and in tests (see enforce.go).
	enforcer Enforcer
}

// New builds an App. Engine may be nil until the service wires the real one.
func New(cfg config.ClientConfig, store *storage.Store, engine Engine, nodes NodesProvider) *App {
	if nodes == nil {
		nodes = NewStaticNodes(nil)
	}
	return &App{cfg: cfg, store: store, engine: engine, nodes: nodes}
}

// SetEngine injects (or swaps) the tunnel engine.
func (a *App) SetEngine(e Engine) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.engine = e
}

// SetNodes swaps the node provider.
func (a *App) SetNodes(p NodesProvider) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nodes = p
}

// IsDemo reports demo mode (seeded fake nodes, isolated from prod state).
func (a *App) IsDemo() bool { return a.demo }
// SetSavePath overrides where UpdateConfig persists (demo isolation).
func (a *App) SetSavePath(path string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.savePath = path
}

// Close releases the wallet bridge and the store. Call on shutdown.
func (a *App) Close() error {
	a.mu.Lock()
	conn := a.wallet
	a.wallet = nil
	a.mu.Unlock()
	closeWallet(conn)
	if a.store == nil {
		return nil
	}
	return a.store.Close()
}

// Config returns a copy of the client config.
func (a *App) Config() config.ClientConfig {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg
}

// UpdateConfig validates, swaps, and persists the client config. An empty
// savePath uses the app save path (demo file in demo mode) or the default
// client path, so settings persist across restarts.
func (a *App) UpdateConfig(cfg config.ClientConfig, savePath string) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if savePath == "" {
		a.mu.RLock()
		savePath = a.savePath
		a.mu.RUnlock()
	}
	if err := cfg.Save(savePath); err != nil {
		return err
	}
	a.mu.Lock()
	a.cfg = cfg
	a.mu.Unlock()
	events.Publish(events.DNS_CHANGED, cfg.DNS.Mode)
	return nil
}

// ListNodes merges provider nodes with local trust/latency observations.
func (a *App) ListNodes() ([]NodeInfo, error) {
	a.mu.RLock()
	p := a.nodes
	a.mu.RUnlock()
	nodes, err := p.ListNodes()
	if err != nil {
		return nil, err
	}
	for i := range nodes {
		if avg, n, err := a.store.AvgLatency(nodes[i].NodeID, 5); err == nil && n > 0 {
			nodes[i].LatencyMs = avg.Milliseconds()
		} else {
			nodes[i].LatencyMs = -1
		}
		if trust, _, err := a.store.GetTrust(nodes[i].NodeID); err == nil {
			nodes[i].Trust = trust
		} else {
			nodes[i].Trust = 0.5
		}
	}
	return nodes, nil
}

// findNode resolves a node by id from the provider.
func (a *App) findNode(id string) (NodeInfo, error) {
	nodes, err := a.ListNodes()
	if err != nil {
		return NodeInfo{}, err
	}
	for _, n := range nodes {
		if n.NodeID == id {
			return n, nil
		}
	}
	return NodeInfo{}, fmt.Errorf("node %q not found", id)
}

// Connect establishes the tunnel to nodeID, or auto-selects when empty.
func (a *App) Connect(nodeID string) error {
	a.mu.Lock()
	if a.node != nil {
		a.mu.Unlock()
		return errors.New("already connected; disconnect first")
	}
	engine := a.engine
	a.mu.Unlock()
	if engine == nil {
		return errors.New("no tunnel engine wired")
	}

	var node NodeInfo
	var err error
	if nodeID == "" {
		node, err = a.AutoSelect()
	} else {
		node, err = a.findNode(nodeID)
	}
	if err != nil {
		return err
	}

	lat, perr := a.ProbeLatency(node)
	if perr == nil {
		node.LatencyMs = lat.Milliseconds()
	}

	priv, err := genPrivateKey()
	if err != nil {
		return err
	}
	dns := a.cfg.DNS.Servers
	if a.cfg.DNS.Mode == config.DNSVeilnet || len(dns) == 0 {
		dns = []string{"10.89.0.1"}
	}
	const tunAddr = "10.89.0.2/32"
	wcfg := WGConfig{
		PrivateKey: priv,
		Addresses:  []string{tunAddr},
		DNS:        dns,
		Peers: []Peer{{
			PublicKey:  node.WGPubkey,
			Endpoint:   node.Endpoint,
			AllowedIPs: []string{"0.0.0.0/0"},
			Keepalive:  25,
		}},
	}
	if err := engine.Start(wcfg); err != nil {
		events.Publish(events.ERROR, err.Error())
		return err
	}

	// Fail closed: a tunnel without its kill switch, DNS and IPv6 posture
	// is exactly the silent leak this project refuses to ship, so tear it
	// back down rather than report PROTECTED.
	if err := a.applyEnforcement(node, tunAddr); err != nil {
		_ = engine.Stop()
		_ = a.clearEnforcement()
		events.Publish(events.ERROR, err.Error())
		return err
	}

	connID, _ := a.store.AddConnection(node.NodeID)
	now := time.Now()
	sess := SessionInfo{
		Active:    true,
		SessionID: newSessionID(),
		NodeID:    node.NodeID,
		StartedAt: now,
	}

	a.mu.Lock()
	a.node = &node
	a.connID = connID
	a.sess = sess
	a.mu.Unlock()

	_ = a.store.SetSession("current_node", node.NodeID)
	_ = a.store.SetSession("current_session", sess.SessionID)

	events.Publish(events.NODE_CONNECTED, node.NodeID)
	events.Publish(events.TUNNEL_STARTED, node.Endpoint)
	events.Publish(events.SESSION_AUTHORIZED, sess.SessionID)
	return nil
}

// Disconnect stops the tunnel and records history.
func (a *App) Disconnect() error {
	a.mu.Lock()
	node := a.node
	connID := a.connID
	engine := a.engine
	a.mu.Unlock()
	if node == nil {
		return errors.New("not connected")
	}
	var rx, tx int64
	if engine != nil {
		st := engine.Statistics()
		rx, tx = st.RxBytes, st.TxBytes
		if err := engine.Stop(); err != nil {
			return err
		}
	}
	// Rules come off only after the tunnel is really down, so there is no
	// window where traffic is unprotected but still flowing.
	if err := a.clearEnforcement(); err != nil {
		events.Publish(events.ERROR, "leak protection cleanup: "+err.Error())
	}
	if connID != 0 {
		_ = a.store.EndConnection(connID, rx, tx)
	}
	_ = a.store.ClearSession()
	a.mu.Lock()
	a.node = nil
	a.connID = 0
	a.sess = SessionInfo{}
	a.circuit = Circuit{}
	a.mu.Unlock()
	events.Publish(events.TUNNEL_STOPPED, node.NodeID)
	events.Publish(events.NODE_DISCONNECTED, node.NodeID)
	return nil
}

// State snapshots observable state. The PROTECTED badge may only render
// when EngineState == UP.
func (a *App) State() ConnState {
	a.mu.RLock()
	node := a.node
	sess := a.sess
	circ := a.circuit
	demo := a.demo
	a.mu.RUnlock()

	st := ConnState{EngineState: StateDown, Demo: demo}
	if a.engine != nil {
		es := a.engine.Status()
		st.EngineState = es.State
		stats := a.engine.Statistics()
		st.RxBytes = stats.RxBytes
		st.TxBytes = stats.TxBytes
	}
	if node != nil {
		cp := *node
		st.Node = &cp
		st.ConnectedAt = sess.StartedAt
		if !sess.StartedAt.IsZero() {
			st.ElapsedSecs = int64(time.Since(sess.StartedAt).Seconds())
		}
	}
	st.Session = sess
	st.Circuit = circ
	st.Payment = a.Payment()
	return st
}

// ProbeLatency measures real TCP connect milliseconds to the node endpoint
// (plus handshake age when already connected) and records the sample.
func (a *App) ProbeLatency(node NodeInfo) (time.Duration, error) {
	host, _, err := net.SplitHostPort(node.Endpoint)
	if err != nil {
		host = node.Endpoint
	}
	timeout := time.Duration(a.cfg.Network.ProbeTimeoutSecs) * time.Second
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 5 * time.Second
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, portOf(node.Endpoint)), timeout)
	rtt := time.Since(start)
	if err != nil {
		return 0, err
	}
	conn.Close()
	_ = a.store.RecordLatency(node.NodeID, rtt)
	return rtt, nil
}

func portOf(endpoint string) string {
	_, port, err := net.SplitHostPort(endpoint)
	if err != nil || port == "" {
		return "51820"
	}
	return port
}

// Session returns current session info.
func (a *App) Session() SessionInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.sess
}


// Payment surfaces explicit-payment state.
func (a *App) Payment() PaymentInfo {
	a.mu.RLock()
	pending := a.pendingApproval
	maxPerHour := a.cfg.Payments.MaxPerHourDero
	a.mu.RUnlock()
	p := PaymentInfo{MaxPerHourDero: maxPerHour, PendingApproval: pending}
	receipts, err := a.store.ListReceipts(100)
	if err != nil {
		return p
	}
	cutoff := time.Now().Add(-time.Hour)
	for i, r := range receipts {
		p.Receipts++
		if r.At.After(cutoff) {
			p.SpentLastHour += r.AmountDero
		}
		if i == 0 {
			p.LastTxID = r.TxID
		}
	}
	return p
}

// RequestPaymentApproval flags a payment needing explicit user approval.
// Nothing is spent; the GUI must confirm out of band.
func (a *App) RequestPaymentApproval() {
	a.mu.Lock()
	a.pendingApproval = true
	a.mu.Unlock()
	events.Publish(events.PAYMENT_REQUESTED, time.Now().UTC().Format(time.RFC3339))
}

// ConfirmPayment records an approved payment receipt (explicit approval only).
func (a *App) ConfirmPayment(amount float64, txid string) error {
	a.mu.Lock()
	nodeID := ""
	if a.node != nil {
		nodeID = a.node.NodeID
	}
	sessID := a.sess.SessionID
	a.pendingApproval = false
	a.mu.Unlock()
	if err := a.store.SaveReceipt(storage.Receipt{
		ID: time.Now().UTC().Format("20060102T150405.000000000"),
		NodeID: nodeID, SessionID: sessID, AmountDero: amount, TxID: txid,
		At: time.Now(),
	}); err != nil {
		return err
	}
	events.Publish(events.PAYMENT_CONFIRMED, txid)
	return nil
}

func genPrivateKey() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw[:]), nil
}

func newSessionID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(raw[:])
}
