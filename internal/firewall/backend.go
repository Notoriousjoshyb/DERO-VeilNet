package firewall

import "github.com/dero-veilnet/veilnet/internal/platform"

// Spec describes the allow-list the kill switch must enforce.
type Spec struct {
	// EndpointIP is the handshake peer IP (allowed UDP out).
	EndpointIP string
	// EndpointPort is the handshake peer UDP port.
	EndpointPort int
	// TunAddr is the local tunnel address (tunnel-local traffic allowed).
	TunAddr string
	// LANAllowed permits direct LAN traffic (printers, NAS).
	LANAllowed bool
}

// Backend owns the OS-specific rule mutation. Implementations are
// per-OS (netsh.go, nft.go, pf.go); selection is per-OS
// (select_windows.go, select_linux.go, select_darwin.go) so shared
// logic never branches on the OS.
type Backend interface {
	platform.FirewallBackend
	// RuleNames lists every rule the backend owns for spec (sentinel +
	// diagnostics). Names must be stable for a given spec.
	RuleNames(spec Spec) []string
	// Enable installs the allow-list for spec.
	Enable(run Runner, spec Spec) error
	// Remove deletes every owned rule named in names. It must be
	// idempotent and leave zero residual rules behind.
	Remove(run Runner, names []string) error
	// SetBlock re-asserts the fail-closed block default. Rules stay.
	SetBlock(run Runner) error
	// Restore reinstates the policy snapshot taken by CurrentPolicy.
	Restore(run Runner, policy string) error
	// CurrentPolicy snapshots the current outbound default so Restore
	// can reinstate it exactly (never brick).
	CurrentPolicy(run Runner) (string, error)
}

// unsupportedBackend fails every mutation with a clear error instead of
// faking protection on OSes without a backend.
type unsupportedBackend struct{ os string }

func (b unsupportedBackend) Name() string { return "unsupported(" + b.os + ")" }
func (b unsupportedBackend) Supports() bool { return false }
func (b unsupportedBackend) RuleNames(Spec) []string { return nil }
func (b unsupportedBackend) Enable(Runner, Spec) error {
	return errUnsupported(b.os)
}
func (b unsupportedBackend) Remove(Runner, []string) error { return errUnsupported(b.os) }
func (b unsupportedBackend) SetBlock(Runner) error         { return errUnsupported(b.os) }
func (b unsupportedBackend) Restore(Runner, string) error  { return errUnsupported(b.os) }
func (b unsupportedBackend) CurrentPolicy(Runner) (string, error) {
	return "", errUnsupported(b.os)
}
