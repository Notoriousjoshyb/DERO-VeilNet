//go:build !windows && !linux && !darwin

package dns

import "runtime"

// selectBackend fails loudly on OSes without a DNS backend instead of
// faking tunnel DNS.
func selectBackend() Backend { return unsupportedBackend{os: runtime.GOOS} }
