// Package transport is the pluggable entry-transport seam.
//
// WireGuard normally speaks plain UDP to the entry node. On a censored
// network that is easy to block, so the roadmap calls for bridge
// transports: a swappable layer that carries the same WireGuard traffic
// over something a censor does not drop.
//
// HONEST STATUS: this package ships the SEAM and one transport, "direct"
// (plain UDP, the default). No obfuscating or censorship-resistant
// transport is shipped, and none is claimed. A transport that is not
// registered is a clear startup error, never a silent fallback to
// direct — a client that thinks it is using a bridge while actually
// sending plain UDP is worse than one that refuses to start.
//
// Third parties add transports by implementing Transport and calling
// Register in an init function. The client selects one by name in
// config (`network.transport`).
package transport

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// DirectName is the built-in plain-UDP transport, and the default.
const DirectName = "direct"

// Transport builds the UDP bind that carries WireGuard traffic.
//
// Returning a conn.Bind (rather than wrapping bytes here) is deliberate:
// it is the exact seam wireguard-go already exposes, so a transport can
// re-frame packets without the tunnel engine knowing or caring.
type Transport interface {
	// Name is the config identifier, lowercase and stable.
	Name() string
	// Description is one line shown by `veilnet --setup`.
	Description() string
	// Obfuscating reports whether this transport actually disguises
	// traffic. "direct" answers false. A transport must not claim true
	// unless it really re-shapes what a censor sees — this flag is what
	// the UI uses to tell the user whether they have protection.
	Obfuscating() bool
	// NewBind creates the bind. endpoint is the entry node's ip:port,
	// which some transports need for a handshake of their own.
	NewBind(endpoint string) (conn.Bind, error)
}

var (
	mu       sync.RWMutex
	registry = map[string]Transport{}
)

// Register adds t. It panics on a duplicate name, because two
// transports answering to one config value is a configuration the user
// cannot reason about.
func Register(t Transport) {
	if t == nil {
		panic("transport: Register(nil)")
	}
	name := strings.ToLower(strings.TrimSpace(t.Name()))
	if name == "" {
		panic("transport: transport with empty name")
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := registry[name]; dup {
		panic("transport: duplicate transport " + name)
	}
	registry[name] = t
}

// Get returns the transport named name ("" means direct). An unknown
// name is an error listing what is available; it never falls back.
func Get(name string) (Transport, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		key = DirectName
	}
	mu.RLock()
	t, ok := registry[key]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf(
			"transport %q is not available in this build (have: %s); "+
				"install a plugin that registers it, or set network.transport to %q",
			name, strings.Join(Names(), ", "), DirectName)
	}
	return t, nil
}

// Names lists registered transports, sorted.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Available reports whether name is registered ("" = direct).
func Available(name string) bool {
	_, err := Get(name)
	return err == nil
}

// directTransport is plain UDP: what WireGuard does with no bridge.
type directTransport struct{}

func (directTransport) Name() string { return DirectName }

func (directTransport) Description() string {
	return "plain UDP to the entry node (no obfuscation, the default)"
}

func (directTransport) Obfuscating() bool { return false }

func (directTransport) NewBind(string) (conn.Bind, error) {
	return conn.NewDefaultBind(), nil
}

func init() { Register(directTransport{}) }
