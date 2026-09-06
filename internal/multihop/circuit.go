// Package multihop builds segmented multi-hop circuits on top of the
// WireGuard data plane. It owns route CONSTRUCTION and VERIFICATION only:
// actual device programming is performed by the tunnel / routing / firewall
// packages owned by TunnelNetEngine. This package never imports them;
// instead it produces plain HopConfig values whose fields map 1:1 onto
// tunnel.WireGuardConfig (see HopConfig.ToWireGuardDoc).
//
//	single-hop (1 hop: client -> exit) — always available, fallback path.
//	two-hop    (2 hops: client -> ENTRY -> EXIT) — segmented circuit, default.
//	three-hop  (3 hops: client -> ENTRY -> MIDDLE -> EXIT) — full separation:
//	entry sees client IP only, middle sees neither end, exit sees
//	destination only. Build with BuildThreeHopCircuit or the canonical
//	BuildRoute; a 2-hop circuit is never reported as 3-hop.
//
// Per-node observability (what each hop learns) is documented in
// observability.go and enforced by the segmented design: the entry hop
// knows the client IP but not the final destination plaintext beyond the
// next hop; the exit hop knows the destination but never the client IP.
package multihop

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// NodeInfo mirrors the registry node metadata fields relevant to circuit
// construction. Full metadata lives in internal/registry (DeroPayRegistry);
// only the fields needed for route construction are duplicated here so this
// package stays decoupled.
type NodeInfo struct {
	NodeID       string
	WGPubKey     string
	Endpoint     string
	Region       string
	Country      string
	City         string
	PricePerHour float64
	CapacityMax  int
	// Dynamic signals used by the latency aggregator / selector.
	Load     float64 // 0..1 fraction of capacity in use
	Latency  float64 // last measured RTT in ms
	Uptime   float64 // 0..1 rolling availability
	History  float64 // 0..1 local-history reliability bonus
	Protocol int
	Bonded   bool
}

// Validate reports whether the node carries enough data to be dialled.
func (n NodeInfo) Validate() error {
	if n.NodeID == "" {
		return errors.New("multihop: node_id empty")
	}
	if n.WGPubKey == "" {
		return fmt.Errorf("multihop: node %q missing wg_pubkey", n.NodeID)
	}
	if n.Endpoint == "" {
		return fmt.Errorf("multihop: node %q missing endpoint", n.NodeID)
	}
	return nil
}

// HopConfig is the per-segment WireGuard configuration produced by the
// circuit builder. Field names intentionally mirror
// tunnel.WireGuardConfig{PrivateKey, Addresses, DNS, Peers[]} so the app
// layer can translate mechanically:
//
//	HopConfig.LocalPrivateKey -> WireGuardConfig.PrivateKey
//	HopConfig.Addresses       -> WireGuardConfig.Addresses
//	HopConfig.DNS             -> WireGuardConfig.DNS
//	HopConfig.Peer            -> WireGuardConfig.Peers[0]
//
// HopConfig carries no secrets itself: LocalPrivateKey is left empty for
// the caller (tunnel owner) to fill from the local key store. Secrets must
// never be placed on-chain (repo-wide constraint).
type HopConfig struct {
	Role            string // "entry" | "exit" | "single" | "middle"(3-hop only)
	NodeID          string
	LocalPrivateKey string // caller fills; empty here by design
	Addresses       []string
	DNS             []string
	Peer            HopPeer
}

// HopPeer mirrors tunnel.Peer{PublicKey, Endpoint, AllowedIPs, Keepalive}.
type HopPeer struct {
	PublicKey  string
	Endpoint   string
	AllowedIPs []string
	Keepalive  int
}

// Circuit is a segmented 1-3 hop path: client -> [ENTRY -> [MIDDLE ->]] EXIT.
type Circuit struct {
	ID        string
	Hops      int // 1, 2, or 3
	Entry     NodeInfo
	Middle    NodeInfo // valid only when Hops == 3
	Exit      NodeInfo
	CreatedAt time.Time
}

// newID returns a random 128-bit hex circuit identifier.
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("c-%d", time.Now().UnixNano())
	}
	return "c-" + hex.EncodeToString(b[:])
}

// BuildSingleHop constructs the 1-hop fallback circuit: client -> node.
// Always available; used when no suitable entry exists or rotation fails.
func BuildSingleHop(node NodeInfo) (*Circuit, error) {
	if err := node.Validate(); err != nil {
		return nil, err
	}
	return &Circuit{
		ID:        newID(),
		Hops:      1,
		Entry:     node,
		Exit:      node,
		CreatedAt: time.Now().UTC(),
	}, nil
}

// BuildTwoHop constructs a segmented ENTRY -> EXIT circuit.
// Entry and exit must be distinct nodes on distinct boxes with valid dial
// data (loop + same-box rejection via checkDistinct).
func BuildTwoHop(entry, exit NodeInfo) (*Circuit, error) {
	if err := entry.Validate(); err != nil {
		return nil, fmt.Errorf("multihop: bad entry: %w", err)
	}
	if err := exit.Validate(); err != nil {
		return nil, fmt.Errorf("multihop: bad exit: %w", err)
	}
	if err := checkDistinct([]NodeInfo{entry, exit}); err != nil {
		return nil, err
	}
	return &Circuit{
		ID:        newID(),
		Hops:      2,
		Entry:     entry,
		Exit:      exit,
		CreatedAt: time.Now().UTC(),
	}, nil
}

// BuildThreeHopCircuit constructs the full ENTRY -> MIDDLE -> EXIT circuit.
// All three nodes must be pairwise distinct on distinct boxes (loop +
// same-box rejection). This is the canonical 3-hop builder: no feature
// flag, no fallback substitution — a 2-hop circuit is never reported as
// 3-hop. (The legacy gated ThreeHopCircuit in threehop.go is retained for
// API compatibility.)
func BuildThreeHopCircuit(entry, middle, exit NodeInfo) (*Circuit, error) {
	if err := entry.Validate(); err != nil {
		return nil, fmt.Errorf("multihop: bad entry: %w", err)
	}
	if err := middle.Validate(); err != nil {
		return nil, fmt.Errorf("multihop: bad middle: %w", err)
	}
	if err := exit.Validate(); err != nil {
		return nil, fmt.Errorf("multihop: bad exit: %w", err)
	}
	if err := checkDistinct([]NodeInfo{entry, middle, exit}); err != nil {
		return nil, err
	}
	return &Circuit{
		ID:        newID(),
		Hops:      3,
		Entry:     entry,
		Middle:    middle,
		Exit:      exit,
		CreatedAt: time.Now().UTC(),
	}, nil
}

// Nodes returns the circuit hops in path order.
func (c *Circuit) Nodes() []NodeInfo {
	if c == nil {
		return nil
	}
	switch c.Hops {
	case 3:
		return []NodeInfo{c.Entry, c.Middle, c.Exit}
	case 1:
		return []NodeInfo{c.Exit}
	default:
		return []NodeInfo{c.Entry, c.Exit}
	}
}

// Countries returns the per-hop countries in path order.
func (c *Circuit) Countries() []string {
	nodes := c.Nodes()
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = n.Country
	}
	return out
}

// ToRoute converts the circuit to its canonical Route for rotation,
// tokens, and quoting. EntryPinned is set by the caller (guard owner).
func (c *Circuit) ToRoute() (*Route, error) {
	if c == nil {
		return nil, errors.New("multihop: nil circuit")
	}
	return BuildRoute(c.Nodes(), BuildOptions{})
}

// Verify re-checks a constructed circuit: distinct hops on distinct boxes,
// dial data present, hop count consistent. The app layer calls Verify
// before handing configs to the tunnel engine.
func (c *Circuit) Verify() error {
	if c == nil {
		return errors.New("multihop: nil circuit")
	}
	if c.ID == "" {
		return errors.New("multihop: circuit id empty")
	}
	switch c.Hops {
	case 1:
		if c.Entry.NodeID == "" || c.Exit.NodeID == "" {
			return errors.New("multihop: single-hop circuit missing node")
		}
		if err := c.Exit.Validate(); err != nil {
			return fmt.Errorf("multihop: single-hop exit invalid: %w", err)
		}
	case 2:
		if err := c.Entry.Validate(); err != nil {
			return fmt.Errorf("multihop: entry invalid: %w", err)
		}
		if err := c.Exit.Validate(); err != nil {
			return fmt.Errorf("multihop: exit invalid: %w", err)
		}
		if err := checkDistinct([]NodeInfo{c.Entry, c.Exit}); err != nil {
			return err
		}
	case 3:
		if err := c.Entry.Validate(); err != nil {
			return fmt.Errorf("multihop: entry invalid: %w", err)
		}
		if err := c.Middle.Validate(); err != nil {
			return fmt.Errorf("multihop: middle invalid: %w", err)
		}
		if err := c.Exit.Validate(); err != nil {
			return fmt.Errorf("multihop: exit invalid: %w", err)
		}
		if err := checkDistinct([]NodeInfo{c.Entry, c.Middle, c.Exit}); err != nil {
			return err
		}
	default:
		return fmt.Errorf("multihop: unsupported hop count %d", c.Hops)
	}
	return nil
}

// EntryConfig returns the local WireGuard segment that reaches the ENTRY
// hop: full-tunnel AllowedIPs so all traffic (including DNS) enters the
// circuit at the entry. The caller fills LocalPrivateKey from the key store.
func (c *Circuit) EntryConfig(dns []string) HopConfig {
	peer := c.Entry
	if c.Hops == 1 {
		peer = c.Exit
	}
	role := "entry"
	if c.Hops == 1 {
		role = "single"
	}
	return HopConfig{
		Role:      role,
		NodeID:    peer.NodeID,
		Addresses: []string{"10.200.0.2/32"},
		DNS:       append([]string(nil), dns...),
		Peer: HopPeer{
			PublicKey:  peer.WGPubKey,
			Endpoint:   peer.Endpoint,
			AllowedIPs: []string{"0.0.0.0/0", "::/0"},
			Keepalive:  25,
		},
	}
}

// ExitDescriptor returns the exit-side routing descriptor the app layer
// forwards (via control plane / IPC) so the ENTRY knows which EXIT to
// chain to. It contains only public dial data — never secret keys.
func (c *Circuit) ExitDescriptor() HopConfig {
	return HopConfig{
		Role:   "exit",
		NodeID: c.Exit.NodeID,
		Peer: HopPeer{
			PublicKey:  c.Exit.WGPubKey,
			Endpoint:   c.Exit.Endpoint,
			AllowedIPs: []string{"0.0.0.0/0", "::/0"},
			Keepalive:  25,
		},
	}
}

// MiddleConfig returns the middle-hop chaining descriptor for 3-hop
// circuits: public dial data the ENTRY forwards so it knows which MIDDLE
// to chain to. Empty NodeID on circuits with fewer than 3 hops.
func (c *Circuit) MiddleConfig() HopConfig {
	if c == nil || c.Hops != 3 {
		return HopConfig{}
	}
	return HopConfig{
		Role:   "middle",
		NodeID: c.Middle.NodeID,
		Peer: HopPeer{
			PublicKey:  c.Middle.WGPubKey,
			Endpoint:   c.Middle.Endpoint,
			AllowedIPs: []string{"0.0.0.0/0", "::/0"},
			Keepalive:  25,
		},
	}
}

// Chain returns the ordered per-hop descriptors (entry[, middle], exit)
// the app layer forwards over the control plane to program the chain.
func (c *Circuit) Chain() []HopConfig {
	if c == nil {
		return nil
	}
	out := make([]HopConfig, 0, c.Hops)
	entry := c.EntryConfig(nil)
	entry.DNS = nil
	out = append(out, entry)
	if c.Hops == 3 {
		out = append(out, c.MiddleConfig())
	}
	out = append(out, c.ExitDescriptor())
	return out
}
