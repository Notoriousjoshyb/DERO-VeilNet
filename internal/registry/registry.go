// Package registry stores node metadata, selects nodes, and mirrors
// writes to the DERO smart contract.
//
// Node metadata (binding contract): {node_id, wg_pubkey, region,
// country, city, endpoint, price_per_hour_dero, capacity_max_clients,
// protocol_version, bond_dero, status, version}.
//
// Identity: the WireGuard public key is the data-plane identity while
// an ed25519 operator key is the control-plane identity; the two are
// bound together in the signed announcement. The registry pins the
// operator key per node_id on first Register (TOFU) and enforces key
// continuity on Update, which blunts Sybil churn: new identities must
// re-post bond (see contracts/veilnet.bas DepositBond).
//
// Persistence is a local JSON file; the DERO-SC mirror goes through
// the SCMirror interface so this package never imports internal/dero
// (no import cycles). A nil mirror means file-only (demo/dev).
package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Status is the node lifecycle state.
type Status string

const (
	StatusActive   Status = "active"
	StatusDisabled Status = "disabled"
)

// CurrentVersion is the registry schema version written into Node.Version.
const CurrentVersion = "1"

// MinBondDERO is the default minimum operator bond. Stores created
// with MinBond <= 0 fall back to it. It blunts Sybil registrations:
// identities are cheap, bonded identities are not.
const MinBondDERO = 10.0

// Node is one exit/relay node advertisement.
type Node struct {
	NodeID             string  `json:"node_id"`
	WGPubKey           string  `json:"wg_pubkey"`
	Region             string  `json:"region"`
	Country            string  `json:"country"`
	City               string  `json:"city"`
	Endpoint           string  `json:"endpoint"`
	PricePerHourDERO   float64 `json:"price_per_hour_dero"`
	CapacityMaxClients int     `json:"capacity_max_clients"`
	ProtocolVersion    int     `json:"protocol_version"`
	BondDERO           float64 `json:"bond_dero"`
	Status             Status  `json:"status"`
	Version            string  `json:"version"`
}

// Validate checks operator-facing invariants. It rejects empty ids,
// malformed endpoints, non-32-byte WireGuard keys, negative prices,
// zero capacity, unknown statuses, and bonds below minBond.
func Validate(n Node, minBond float64) error {
	if strings.TrimSpace(n.NodeID) == "" {
		return errors.New("registry: empty node_id")
	}
	if strings.ContainsAny(n.NodeID, " \t\n/") {
		return errors.New("registry: node_id must not contain whitespace or slashes")
	}
	raw, err := base64.StdEncoding.DecodeString(n.WGPubKey)
	if err != nil {
		if raw, err = base64.RawURLEncoding.DecodeString(n.WGPubKey); err != nil {
			return fmt.Errorf("registry: wg_pubkey not base64: %w", err)
		}
	}
	if len(raw) != 32 {
		return fmt.Errorf("registry: wg_pubkey must decode to 32 bytes, got %d", len(raw))
	}
	host, port, err := net.SplitHostPort(n.Endpoint)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("registry: endpoint must be host:port: %w", err)
	}
	if n.PricePerHourDERO < 0 {
		return errors.New("registry: negative price_per_hour_dero")
	}
	if n.CapacityMaxClients <= 0 {
		return errors.New("registry: capacity_max_clients must be > 0")
	}
	if n.ProtocolVersion <= 0 {
		return errors.New("registry: protocol_version must be > 0")
	}
	if minBond <= 0 {
		minBond = MinBondDERO
	}
	if n.BondDERO < minBond {
		return fmt.Errorf("registry: bond_dero %.4f below minimum %.4f", n.BondDERO, minBond)
	}
	if n.Status != StatusActive && n.Status != StatusDisabled {
		return fmt.Errorf("registry: unknown status %q", n.Status)
	}
	return nil
}

// canonicalJSON renders n with fixed key order for signing.
func canonicalJSON(n Node) ([]byte, error) {
	// Struct field order is the canonical order; disable HTML escaping
	// so endpoints and regions round-trip byte-identically.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(n); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Announcement is a signed node advertisement. Payload is the canonical
// node JSON; Signature is ed25519 over Payload; OperatorKey is the
// 32-byte ed25519 public key of the signer.
type Announcement struct {
	Payload     []byte `json:"payload"`
	Signature   []byte `json:"signature"`
	OperatorKey []byte `json:"operator_key"`
}

// Sign binds n to priv and returns the announcement. The caller sets
// n.Status before signing (Register: active; remote disable: disabled).
func Sign(n Node, priv ed25519.PrivateKey) (Announcement, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Announcement{}, errors.New("registry: bad ed25519 private key size")
	}
	payload, err := canonicalJSON(n)
	if err != nil {
		return Announcement{}, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return Announcement{
		Payload:     payload,
		Signature:   ed25519.Sign(priv, payload),
		OperatorKey: []byte(pub),
	}, nil
}

// Verify checks the signature and decodes the payload. It returns the
// node and the operator public key. Pinning (same key per node_id) is
// enforced by Store, not here.
func Verify(a Announcement) (Node, ed25519.PublicKey, error) {
	if len(a.OperatorKey) != ed25519.PublicKeySize {
		return Node{}, nil, errors.New("registry: bad operator key size")
	}
	if len(a.Signature) != ed25519.SignatureSize {
		return Node{}, nil, errors.New("registry: bad signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(a.OperatorKey), a.Payload, a.Signature) {
		return Node{}, nil, errors.New("registry: signature verification failed")
	}
	var n Node
	if err := json.Unmarshal(a.Payload, &n); err != nil {
		return Node{}, nil, fmt.Errorf("registry: bad payload: %w", err)
	}
	return n, ed25519.PublicKey(a.OperatorKey), nil
}

// SCMirror receives registry writes destined for the DERO smart
// contract (contracts/veilnet.bas). Implementations submit through the
// wallet scinvoke path; a nil mirror disables chain writes. op is one
// of RegisterNode, UpdateNode, DisableNode, SetPrice.
type SCMirror interface {
	Mirror(ctx context.Context, op string, n Node) error
}

// Store is a concurrency-safe node registry with JSON-file persistence
// and an optional DERO-SC mirror.
type Store struct {
	mu     sync.RWMutex
	nodes  map[string]Node
	opKeys map[string][]byte // node_id -> pinned ed25519 operator key
	mirror SCMirror
	path   string
	minBond float64
}

// Options tunes a Store.
type Options struct {
	// Mirror receives chain writes; nil means file-only.
	Mirror SCMirror
	// MinBond overrides MinBondDERO; <= 0 keeps the default.
	MinBond float64
}

// NewStore returns a store persisting to path ("" disables the file).
func NewStore(path string, opts Options) *Store {
	minBond := opts.MinBond
	if minBond <= 0 {
		minBond = MinBondDERO
	}
	return &Store{
		nodes:   make(map[string]Node),
		opKeys:  make(map[string][]byte),
		mirror:  opts.Mirror,
		path:    path,
		minBond: minBond,
	}
}

func (s *Store) checkKeyContinuity(n Node, op ed25519.PublicKey) error {
	if pinned, ok := s.opKeys[n.NodeID]; ok {
		if !bytes.Equal(pinned, []byte(op)) {
			return errors.New("registry: operator key changed for known node_id (re-registration with fresh bond required)")
		}
	}
	return nil
}

func (s *Store) put(n Node, op ed25519.PublicKey) {
	s.nodes[n.NodeID] = n
	if _, ok := s.opKeys[n.NodeID]; !ok {
		cp := make([]byte, len(op))
		copy(cp, op)
		s.opKeys[n.NodeID] = cp
	}
}

// Register pins a new node_id to its operator key and stores it.
// Re-registering a known node_id with a DIFFERENT key is rejected;
// the same key must use Update.
func (s *Store) Register(ctx context.Context, a Announcement) error {
	n, op, err := Verify(a)
	if err != nil {
		return err
	}
	if err := Validate(n, s.minBond); err != nil {
		return err
	}
	s.mu.Lock()
	if _, exists := s.nodes[n.NodeID]; exists {
		if err := s.checkKeyContinuity(n, op); err != nil {
			s.mu.Unlock()
			return err
		}
		s.mu.Unlock()
		return fmt.Errorf("registry: %s already registered (use Update)", n.NodeID)
	}
	s.put(n, op)
	mirror := s.mirror
	s.mu.Unlock()
	if err := s.save(); err != nil {
		return err
	}
	if mirror != nil {
		if err := mirror.Mirror(ctx, "RegisterNode", n); err != nil {
			return fmt.Errorf("registry: SC mirror RegisterNode: %w", err)
		}
	}
	return nil
}

// Update replaces the advertisement for a known node_id. The signer
// must hold the pinned operator key.
func (s *Store) Update(ctx context.Context, a Announcement) error {
	n, op, err := Verify(a)
	if err != nil {
		return err
	}
	if err := Validate(n, s.minBond); err != nil {
		return err
	}
	s.mu.Lock()
	if _, exists := s.nodes[n.NodeID]; !exists {
		s.mu.Unlock()
		return fmt.Errorf("registry: unknown node %s (use Register)", n.NodeID)
	}
	if err := s.checkKeyContinuity(n, op); err != nil {
		s.mu.Unlock()
		return err
	}
	s.put(n, op)
	mirror := s.mirror
	s.mu.Unlock()
	if err := s.save(); err != nil {
		return err
	}
	if mirror != nil {
		if err := mirror.Mirror(ctx, "UpdateNode", n); err != nil {
			return fmt.Errorf("registry: SC mirror UpdateNode: %w", err)
		}
	}
	return nil
}

// Disable marks a node disabled locally and mirrors DisableNode.
// Remote operators disable via Update with Status disabled; this is
// the local-admin path (no signature: the caller owns the file).
func (s *Store) Disable(ctx context.Context, nodeID string) error {
	s.mu.Lock()
	n, ok := s.nodes[nodeID]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("registry: unknown node %s", nodeID)
	}
	n.Status = StatusDisabled
	s.nodes[nodeID] = n
	mirror := s.mirror
	s.mu.Unlock()
	if err := s.save(); err != nil {
		return err
	}
	if mirror != nil {
		if err := mirror.Mirror(ctx, "DisableNode", n); err != nil {
			return fmt.Errorf("registry: SC mirror DisableNode: %w", err)
		}
	}
	return nil
}

// SetPrice changes the hourly price locally and mirrors SetPrice.
func (s *Store) SetPrice(ctx context.Context, nodeID string, price float64) error {
	if price < 0 {
		return errors.New("registry: negative price")
	}
	s.mu.Lock()
	n, ok := s.nodes[nodeID]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("registry: unknown node %s", nodeID)
	}
	n.PricePerHourDERO = price
	s.nodes[nodeID] = n
	mirror := s.mirror
	s.mu.Unlock()
	if err := s.save(); err != nil {
		return err
	}
	if mirror != nil {
		if err := mirror.Mirror(ctx, "SetPrice", n); err != nil {
			return fmt.Errorf("registry: SC mirror SetPrice: %w", err)
		}
	}
	return nil
}

// Get returns the node and whether it is known.
func (s *Store) Get(nodeID string) (Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.nodes[nodeID]
	return n, ok
}

// List returns all nodes (active and disabled).
func (s *Store) List() []Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, n)
	}
	return out
}

// Active returns nodes with Status active.
func (s *Store) Active() []Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Node
	for _, n := range s.nodes {
		if n.Status == StatusActive {
			out = append(out, n)
		}
	}
	return out
}

// save writes the JSON file. "" path means memory-only.
func (s *Store) save() error {
	if s.path == "" {
		return nil
	}
	s.mu.RLock()
	snap := make(map[string]Node, len(s.nodes))
	for k, v := range s.nodes {
		snap[k] = v
	}
	s.mu.RUnlock()
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Load reads the JSON file back. Missing file means an empty store.
// Operator-key pins are NOT persisted: on restart the first Update
// re-pins, and a changed key is rejected only once a pin exists.
// (Bond continuity across restarts is enforced on-chain instead.)
func (s *Store) Load() error {
	if s.path == "" {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var snap map[string]Node
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, n := range snap {
		if err := Validate(n, s.minBond); err != nil {
			continue // skip corrupt entries, keep the rest
		}
		s.nodes[id] = n
	}
	return nil
}
