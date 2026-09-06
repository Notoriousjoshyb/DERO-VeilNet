package routing

import (
	"fmt"

	"github.com/dero-veilnet/veilnet/internal/platform"
)

// Backend owns the OS-specific route mutation. Implementations are per-OS
// (netsh.go, iproute.go, bsdroute.go); selection is per-OS
// (select_windows.go, select_linux.go, select_darwin.go) so shared
// logic never branches on the OS.
type Backend interface {
	platform.RouteBackend
	// Add installs one route.
	Add(run Runner, r Route) error
	// Delete removes one route previously added.
	Delete(run Runner, r Route) error
	// SetMetric sets the interface metric.
	SetMetric(run Runner, iface string, metric int) error
	// GetMetric queries the current interface metric for restore.
	// Backends without metric queries return an error and the caller
	// skips restore recording (never fatal).
	GetMetric(run Runner, iface string) (int, error)
	// BlockIPv6 blocks IPv6 egress outside the tunnel.
	BlockIPv6(run Runner, tunnelIface string) error
	// RestoreIPv6 reverses BlockIPv6.
	RestoreIPv6(run Runner) error
}

// errUnsupported reports an OS without a routing backend. Failing loudly
// here is load-bearing: silently skipping routes would leak traffic
// outside the tunnel.
func errUnsupported(os string) error {
	return fmt.Errorf("routing: no backend on %s (refusing to run without tunnel routes)", os)
}

// unsupportedBackend fails every mutation with a clear error instead of
// faking tunnel routing on OSes without a backend.
type unsupportedBackend struct{ os string }

func (b unsupportedBackend) Name() string { return "unsupported(" + b.os + ")" }
func (b unsupportedBackend) Supports() bool { return false }
func (b unsupportedBackend) Add(Runner, Route) error {
	return errUnsupported(b.os)
}
func (b unsupportedBackend) Delete(Runner, Route) error {
	return errUnsupported(b.os)
}
func (b unsupportedBackend) SetMetric(Runner, string, int) error {
	return errUnsupported(b.os)
}
func (b unsupportedBackend) GetMetric(Runner, string) (int, error) {
	return 0, errUnsupported(b.os)
}
func (b unsupportedBackend) BlockIPv6(Runner, string) error {
	return errUnsupported(b.os)
}
func (b unsupportedBackend) RestoreIPv6(Runner) error {
	return errUnsupported(b.os)
}
