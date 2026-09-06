//go:build !windows && !linux && !darwin

package routing

import "runtime"

// selectBackend fails loudly on OSes without a routing backend instead
// of leaking traffic outside the tunnel.
func selectBackend() Backend { return unsupportedBackend{os: runtime.GOOS} }
