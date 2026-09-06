package platform

import (
	"sort"
	"sync"
)

// Runner executes one OS command and returns combined output. Subsystem
// managers accept this interface so tests can substitute a fake.
type Runner interface {
	Run(name string, args ...string) (string, error)
}

// FirewallBackend is the probe contract every kill-switch backend satisfies.
// The full rule-mutation surface lives in the owning subsystem package so
// this package never imports it (no cycles).
type FirewallBackend interface {
	// Name identifies the backend (netsh, nftables, pf).
	Name() string
	// Supports reports whether this backend can run on the current OS.
	Supports() bool
}

// DNSBackend is the probe contract for DNS manager backends.
type DNSBackend interface {
	Name() string
	Supports() bool
}

// RouteBackend is the probe contract for routing backends.
type RouteBackend interface {
	Name() string
	Supports() bool
}

// Kind identifies a backend family in the registry.
type Kind string

// Backend kinds.
const (
	KindFirewall Kind = "firewall"
	KindDNS      Kind = "dns"
	KindRoute    Kind = "route"
)

var (
	regMu sync.RWMutex
	reg   = map[Kind]map[string]func() bool{}
)

// Register records a backend's Supports probe under its kind and name.
// Backends call this from init.
func Register(kind Kind, name string, supports func() bool) {
	regMu.Lock()
	defer regMu.Unlock()
	m := reg[kind]
	if m == nil {
		m = map[string]func() bool{}
		reg[kind] = m
	}
	m[name] = supports
}

// Available lists registered backend names for a kind, sorted.
func Available(kind Kind) []string {
	regMu.RLock()
	defer regMu.RUnlock()
	var out []string
	for name := range reg[kind] {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Supported reports the registered Supports probe for kind/name.
// Unknown names report false.
func Supported(kind Kind, name string) bool {
	regMu.RLock()
	defer regMu.RUnlock()
	probe := reg[kind][name]
	if probe == nil {
		return false
	}
	return probe()
}
