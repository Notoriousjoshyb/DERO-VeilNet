package dns

import "github.com/dero-veilnet/veilnet/internal/platform"

// Backend owns the OS-specific DNS mutation. Implementations are per-OS
// (netsh.go, resolved.go, scutil.go); selection is per-OS
// (select_windows.go, select_linux.go, select_darwin.go) so shared
// logic never branches on the OS.
type Backend interface {
	platform.DNSBackend
	// Current returns the interface's present resolvers (snapshot source).
	Current(run Runner, iface string) []string
	// Set installs servers as the interface resolvers, including any
	// OS catch-all (NRPT on Windows).
	Set(run Runner, iface string, servers []string) error
	// RegisterDOH registers DoH templates before Set. Backends without
	// OS DoH support return an explicit error (never silently downgrade).
	RegisterDOH(run Runner, servers []string) error
	// Restore removes VeilNet state and reinstates the prior resolvers.
	Restore(run Runner, iface string, prior []string) error
	// Effective returns the currently effective resolver IPs for leak
	// detection.
	Effective(run Runner, iface string) []string
}

// unsupportedBackend fails every mutation with a clear error instead of
// faking DNS protection on OSes without a backend.
type unsupportedBackend struct{ os string }

func (b unsupportedBackend) Name() string     { return "unsupported(" + b.os + ")" }
func (b unsupportedBackend) Supports() bool  { return false }
func (b unsupportedBackend) Current(Runner, string) []string { return nil }
func (b unsupportedBackend) Set(Runner, string, []string) error {
	return errUnsupported(b.os)
}
func (b unsupportedBackend) RegisterDOH(Runner, []string) error {
	return errUnsupported(b.os)
}
func (b unsupportedBackend) Restore(Runner, string, []string) error {
	return errUnsupported(b.os)
}
func (b unsupportedBackend) Effective(Runner, string) []string { return nil }
