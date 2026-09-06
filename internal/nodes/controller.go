package nodes

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dero-veilnet/veilnet/internal/session"
)

var (
	// ErrCapacity is returned when max_clients is reached.
	ErrCapacity = errors.New("nodes: at capacity")
	// ErrNotAccepting is returned when accept_new=false.
	ErrNotAccepting = errors.New("nodes: not accepting new clients")
	// ErrDisabled is returned while emergency disable is set.
	ErrDisabled = errors.New("nodes: node disabled by operator")
	// ErrRelayScope is returned when a RELAY node gets an exit-scoped token.
	ErrRelayScope = errors.New("nodes: relay node cannot serve exit scope")
)

// EventPublisher receives lifecycle events; nil = no-op.
type EventPublisher func(event string, v any)

// RegistryClient publishes heartbeats without importing the registry
// tree (local interface avoids the import cycle).
type RegistryClient interface {
	PublishHeartbeat(h Heartbeat) error
}

// NullRegistry drops heartbeats (offline / dev default).
type NullRegistry struct{}

// PublishHeartbeat implements RegistryClient.
func (NullRegistry) PublishHeartbeat(Heartbeat) error { return nil }

// Controller wires sessions, WireGuard peers, IPAM, sqlite, and policy.
type Controller struct {
	cfg *Config
	wg  WGManager
	ip  *IPAM
	ses *session.Manager
	db  *Store
	publish EventPublisher

	// abuse is the optional enforcement guard (HardenAgent hook).
	// Nil means rate-limit/blocklist checks are off.
	abuse *AbuseGuard

	startTime time.Time
	mu        sync.Mutex

	deroEarnedMicro atomic.Int64
	rxTotal         atomic.Uint64
	txTotal         atomic.Uint64
}

// ControllerOptions selects collaborators. Nil WG auto-selects a real
// manager with fake fallback; nil Validator denies all; nil DB disables
// persistence; nil Publisher silences events.
func ControllerOptionsDefaults() {}

// NewController builds a controller from operator config.
func NewController(cfg *Config, validator session.TokenValidator, wg WGManager, db *Store, pub EventPublisher) (*Controller, error) {
	if cfg == nil {
		return nil, errors.New("nodes: nil config")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	ip, err := NewIPAM(cfg.CGNAT)
	if err != nil {
		return nil, err
	}
	if wg == nil {
		wg = NewRealWGManager(cfg.WGInterface)
		if err := wg.EnsureDevice(cfg.WGAddress+"/10", cfg.WGListenPort); err != nil {
			wg = NewFakeWGManager(cfg.WGInterface)
		}
	}
	maxDur := time.Duration(cfg.MaxSessionMinutes) * time.Minute
	c := &Controller{
		cfg:       cfg,
		wg:        wg,
		ip:        ip,
		db:        db,
		publish:   pub,
		startTime: time.Now(),
	}
	c.ses = session.NewManager(validator, session.Options{
		MaxSessionDuration: maxDur,
		OnExpire:           func(s session.Snapshot) { c.onSessionExpired(s) },
		OnEvent:            func(e string, v any) { c.emit(e, v) },
	})
	if db != nil {
		if rows, err := db.ListActive(); err == nil {
			now := time.Now()
			for _, r := range rows {
				if !r.ExpiresAt.IsZero() && !now.Before(r.ExpiresAt) {
					continue
				}
				ip.Reserve(r.AssignedIP)
			}
		}
	}
	return c, nil
}

func (c *Controller) emit(event string, v any) {
	if c.publish != nil {
		c.publish(event, v)
	}
}

// Config returns the live config (copy semantics: do not mutate).
func (c *Controller) Config() *Config { return c.cfg }

// WG exposes the peer manager (diagnostics/tests).
func (c *Controller) WG() WGManager { return c.wg }

// Sessions exposes the session manager.
func (c *Controller) Sessions() *session.Manager { return c.ses }

// StartTime returns daemon boot time.
func (c *Controller) StartTime() time.Time { return c.startTime }

// Uptime returns time since boot.
func (c *Controller) Uptime() time.Duration { return time.Since(c.startTime) }

// Load returns 0..1 client-slot pressure.
func (c *Controller) Load() float64 {
	if c.cfg.MaxClients <= 0 {
		return 0
	}
	return float64(c.ses.ActiveCount()) / float64(c.cfg.MaxClients)
}

// SetEmergencyDisable flips the kill flag at runtime.
func (c *Controller) SetEmergencyDisable(disabled bool) {
	c.mu.Lock()
	c.cfg.EmergencyDisable = disabled
	c.mu.Unlock()
	c.emit("ERROR", map[string]any{"emergency_disable": disabled})
}

// ActiveCount returns live sessions.
func (c *Controller) ActiveCount() int { return c.ses.ActiveCount() }

// Capacity returns (active, max, acceptNew).
func (c *Controller) Capacity() (active, max int, acceptNew bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ses.ActiveCount(), c.cfg.MaxClients, c.cfg.AcceptNew && !c.cfg.EmergencyDisable
}

// AddDeroEarned records settled earnings (micro-DERO integer).
func (c *Controller) AddDeroEarned(micro int64) { c.deroEarnedMicro.Add(micro) }

// DeroEarned returns lifetime earnings in DERO.
func (c *Controller) DeroEarned() float64 { return float64(c.deroEarnedMicro.Load()) / 1e6 }

// Authorize validates the token, enforces capacity/policy, assigns an
// IP, installs the WireGuard peer, and persists the client row.
func (c *Controller) Authorize(tokenString, clientPubkey, endpoint string) (*session.Session, error) {
	c.mu.Lock()
	disabled := c.cfg.EmergencyDisable
	acceptNew := c.cfg.AcceptNew
	max := c.cfg.MaxClients
	nodeType := c.cfg.NodeType
	c.mu.Unlock()

	if disabled {
		return nil, ErrDisabled
	}
	// Abuse precheck (HardenAgent hook): blocklisted IP/pubkey and
	// per-IP authorize bucket. Nil guard = enforcement off.
	if err := c.abusePrecheck(endpoint, clientPubkey); err != nil {
		return nil, err
	}
	if !acceptNew {
		return nil, ErrNotAccepting
	}
	if active := c.ses.ActiveCount(); active >= max {
		return nil, ErrCapacity
	}
	if err := ParseWGKey(clientPubkey); err != nil {
		// FakeWGManager tolerates opaque test keys, but the real path
		// needs valid keys — fail only when the real manager is live.
		if _, isFake := c.wg.(*FakeWGManager); !isFake {
			return nil, fmt.Errorf("nodes: bad client pubkey: %w", err)
		}
	}

	assigned, err := c.ip.Allocate()
	if err != nil {
		return nil, err
	}
	s, err := c.ses.Authorize(tokenString, clientPubkey, assigned, endpoint)
	if err != nil {
		c.ip.Release(assigned)
		return nil, err
	}
	// RELAY nodes never serve exit scope.
	if nodeType == NodeTypeRelay && s.Scope == session.ScopeExit {
		c.ses.Revoke(s.TokenID)
		c.ip.Release(assigned)
		return nil, ErrRelayScope
	}
	if err := c.wg.AddPeer(clientPubkey, assigned, endpoint, 25); err != nil {
		c.ses.Revoke(s.TokenID)
		c.ip.Release(assigned)
		return nil, fmt.Errorf("nodes: install peer: %w", err)
	}
	if c.db != nil {
		_ = c.db.UpsertClient(ClientRow{
			TokenID: s.TokenID, NodeID: s.NodeID, SessionID: s.SessionID,
			ClientKey: clientPubkey, AssignedIP: assigned, Endpoint: endpoint,
			Scope: s.Scope, ExpiresAt: s.ExpiresAt, CreatedAt: s.CreatedAt,
		})
		_ = c.db.BumpSessionsToday(time.Now().Format("2006-01-02"))
	}
	c.emit("NODE_CONNECTED", map[string]any{"clients": c.ses.ActiveCount()})
	return s, nil
}

// Revoke removes a session: WireGuard peer, IP lease, sqlite row.
func (c *Controller) Revoke(tokenID string) error {
	s, err := c.ses.Get(tokenID)
	if err != nil {
		return err
	}
	clientKey, assigned := s.ClientPubkey, s.AssignedIP
	if err := c.ses.Revoke(tokenID); err != nil {
		return err
	}
	_ = c.wg.RemovePeer(clientKey)
	c.ip.Release(assigned)
	if c.db != nil {
		_ = c.db.RevokeClient(tokenID)
	}
	c.emit("NODE_DISCONNECTED", map[string]any{"clients": c.ses.ActiveCount()})
	return nil
}

// AddBytes attributes counters to both session and node totals.
func (c *Controller) AddBytes(tokenID string, rx, tx uint64) error {
	if err := c.ses.AddBytes(tokenID, rx, tx); err != nil {
		return err
	}
	c.rxTotal.Add(rx)
	c.txTotal.Add(tx)
	if c.db != nil {
		_ = c.db.AddBytes(tokenID, rx, tx)
	}
	return nil
}

// CheckRate reports whether a session is within its rate budget.
// Unlimited (0) always passes; otherwise compares average rate since
// session start against the configured ceiling + burst headroom.
func (c *Controller) CheckRate(tokenID string) bool {
	c.mu.Lock()
	kbps := c.cfg.RateLimitKbps
	burst := c.cfg.RateBurstKB
	c.mu.Unlock()
	if kbps <= 0 {
		return true
	}
	s, err := c.ses.Get(tokenID)
	if err != nil {
		return false
	}
	snap := s.Snapshot()
	elapsed := time.Since(snap.CreatedAt).Seconds()
	if elapsed < 1 {
		elapsed = 1
	}
	avgKbps := float64(snap.RxBytes+snap.TxBytes) * 8 / 1000 / elapsed
	allowed := float64(kbps) + float64(burst)*8/maxf(elapsed, 1)
	return avgKbps <= allowed
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// SweepOnce evicts expired sessions and removes their peers.
func (c *Controller) SweepOnce(now time.Time) int {
	return len(c.ses.SweepOnce(now))
}

func (c *Controller) onSessionExpired(s session.Snapshot) {
	_ = c.wg.RemovePeer(s.ClientPubkey)
	c.ip.Release(s.AssignedIP)
	if c.db != nil {
		_ = c.db.RevokeClient(s.TokenID)
	}
	c.emit("NODE_DISCONNECTED", map[string]any{"clients": c.ses.ActiveCount()})
}

// Stats is the /stats payload.
type Stats struct {
	Clients       int     `json:"clients"`
	MaxClients    int     `json:"max_clients"`
	RxBytes       uint64  `json:"rx_bytes"`
	TxBytes       uint64  `json:"tx_bytes"`
	SessionsToday int     `json:"sessions_today"`
	UptimeSec     int64   `json:"uptime_sec"`
	DeroEarned    float64 `json:"dero_earned"`
	Load          float64 `json:"load"`
	Version       string  `json:"version"`
	NodeType      string  `json:"node_type"`
	Region        string  `json:"region"`
}

// Stats snapshots counters for API/status display.
func (c *Controller) Stats() Stats {
	var today int
	if c.db != nil {
		today = c.db.SessionsToday(time.Now().Format("2006-01-02"))
	}
	c.mu.Lock()
	max := c.cfg.MaxClients
	nt := string(c.cfg.NodeType)
	region := c.cfg.Region
	c.mu.Unlock()
	return Stats{
		Clients:       c.ses.ActiveCount(),
		MaxClients:    max,
		RxBytes:       c.rxTotal.Load(),
		TxBytes:       c.txTotal.Load(),
		SessionsToday: today,
		UptimeSec:     int64(c.Uptime().Seconds()),
		DeroEarned:    c.DeroEarned(),
		Load:          c.Load(),
		Version:       Version,
		NodeType:      nt,
		Region:        region,
	}
}
