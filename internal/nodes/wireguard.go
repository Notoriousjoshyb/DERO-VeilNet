package nodes

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WGPeer is a point-in-time view of one WireGuard peer.
type WGPeer struct {
	PublicKey     string
	AllowedIP     string
	Endpoint      string
	LastHandshake time.Time
	RxBytes       uint64
	TxBytes       uint64
}

// WGManager abstracts peer add/remove so the daemon runs on machines
// without WireGuard (degraded mode) and tests run without privileges.
type WGManager interface {
	Name() string
	EnsureDevice(addressCIDR string, listenPort int) error
	AddPeer(publicKey, allowedIP32, endpoint string, keepalive int) error
	RemovePeer(publicKey string) error
	HasPeer(publicKey string) bool
	ListPeers() []WGPeer
	Close() error
}

// ParseWGKey validates a base64 WireGuard key.
func ParseWGKey(s string) error {
	_, err := wgtypes.ParseKey(s)
	return err
}

// --- Real implementation via wgctrl ---

// RealWGManager controls a kernel/userspace WireGuard device.
type RealWGManager struct {
	iface  string
	mu     sync.Mutex
	client *wgctrl.Client
}

// NewRealWGManager targets iface (e.g. "veilnet0").
func NewRealWGManager(iface string) *RealWGManager { return &RealWGManager{iface: iface} }

// Name implements WGManager.
func (m *RealWGManager) Name() string { return m.iface }

func (m *RealWGManager) lazy() (*wgctrl.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client != nil {
		return m.client, nil
	}
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("nodes: wgctrl open: %w", err)
	}
	m.client = c
	return c, nil
}

// EnsureDevice verifies the interface exists. Creation itself is left
// to the OS setup (admin scripts in docs/NODE_OPERATOR.md) — the
// daemon never guesses privileged topology.
func (m *RealWGManager) EnsureDevice(addressCIDR string, listenPort int) error {
	c, err := m.lazy()
	if err != nil {
		return err
	}
	dev, err := c.Device(m.iface)
	if err != nil {
		return fmt.Errorf("nodes: wireguard device %q missing (create it per docs/NODE_OPERATOR.md): %w", m.iface, err)
	}
	_ = addressCIDR
	_ = listenPort
	_ = dev
	return nil
}

// AddPeer adds or updates a peer pinned to a single /32.
func (m *RealWGManager) AddPeer(publicKey, allowedIP32, endpoint string, keepalive int) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("nodes: bad peer pubkey: %w", err)
	}
	ip := net.ParseIP(allowedIP32)
	if ip == nil {
		return fmt.Errorf("nodes: bad allowed ip %q", allowedIP32)
	}
	allowed := net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
	cfg := wgtypes.PeerConfig{
		PublicKey:         key,
		ReplaceAllowedIPs: true,
		AllowedIPs:        []net.IPNet{allowed},
	}
	if endpoint != "" {
		addr, err := net.ResolveUDPAddr("udp", endpoint)
		if err == nil {
			cfg.Endpoint = addr
		}
	}
	if keepalive > 0 {
		d := time.Duration(keepalive) * time.Second
		cfg.PersistentKeepaliveInterval = &d
	}
	c, err := m.lazy()
	if err != nil {
		return err
	}
	return c.ConfigureDevice(m.iface, wgtypes.Config{Peers: []wgtypes.PeerConfig{cfg}})
}

// RemovePeer deletes a peer.
func (m *RealWGManager) RemovePeer(publicKey string) error {
	key, err := wgtypes.ParseKey(publicKey)
	if err != nil {
		return fmt.Errorf("nodes: bad peer pubkey: %w", err)
	}
	c, err := m.lazy()
	if err != nil {
		return err
	}
	return c.ConfigureDevice(m.iface, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{PublicKey: key, Remove: true}},
	})
}

// HasPeer reports peer presence.
func (m *RealWGManager) HasPeer(publicKey string) bool {
	for _, p := range m.ListPeers() {
		if p.PublicKey == publicKey {
			return true
		}
	}
	return false
}

// ListPeers enumerates current peers.
func (m *RealWGManager) ListPeers() []WGPeer {
	c, err := m.lazy()
	if err != nil {
		return nil
	}
	dev, err := c.Device(m.iface)
	if err != nil {
		return nil
	}
	out := make([]WGPeer, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		allowed := ""
		if len(p.AllowedIPs) > 0 {
			allowed = p.AllowedIPs[0].String()
		}
		ep := ""
		if p.Endpoint != nil {
			ep = p.Endpoint.String()
		}
		out = append(out, WGPeer{
			PublicKey:     p.PublicKey.String(),
			AllowedIP:     allowed,
			Endpoint:      ep,
			LastHandshake: p.LastHandshakeTime,
			RxBytes:       uint64(p.ReceiveBytes),
			TxBytes:       uint64(p.TransmitBytes),
		})
	}
	return out
}

// Close releases the wgctrl handle.
func (m *RealWGManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client == nil {
		return nil
	}
	err := m.client.Close()
	m.client = nil
	return err
}

// --- Fake for tests / machines without WireGuard ---

// FakeWGManager is an in-memory WGManager.
type FakeWGManager struct {
	mu    sync.Mutex
	iface string
	peers map[string]WGPeer
}

// NewFakeWGManager builds an in-memory manager.
func NewFakeWGManager(iface string) *FakeWGManager {
	if iface == "" {
		iface = "veilnet0"
	}
	return &FakeWGManager{iface: iface, peers: make(map[string]WGPeer)}
}

// Name implements WGManager.
func (f *FakeWGManager) Name() string { return f.iface }

// EnsureDevice implements WGManager (always succeeds).
func (f *FakeWGManager) EnsureDevice(string, int) error { return nil }

// AddPeer implements WGManager.
func (f *FakeWGManager) AddPeer(publicKey, allowedIP32, endpoint string, keepalive int) error {
	if _, err := wgtypes.ParseKey(publicKey); err != nil {
		// Accept syntactically plausible test keys without failing:
		if publicKey == "" {
			return errors.New("nodes: empty peer pubkey")
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peers[publicKey] = WGPeer{PublicKey: publicKey, AllowedIP: allowedIP32, Endpoint: endpoint}
	return nil
}

// RemovePeer implements WGManager.
func (f *FakeWGManager) RemovePeer(publicKey string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.peers, publicKey)
	return nil
}

// HasPeer implements WGManager.
func (f *FakeWGManager) HasPeer(publicKey string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.peers[publicKey]
	return ok
}

// ListPeers implements WGManager.
func (f *FakeWGManager) ListPeers() []WGPeer {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]WGPeer, 0, len(f.peers))
	for _, p := range f.peers {
		out = append(out, p)
	}
	return out
}

// Close implements WGManager.
func (f *FakeWGManager) Close() error { return nil }
