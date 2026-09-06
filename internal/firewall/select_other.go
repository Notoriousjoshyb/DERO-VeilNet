//go:build !windows && !linux && !darwin

package firewall

import "runtime"

// selectBackend fails loudly on OSes without a kill-switch backend
// instead of faking protection.
func selectBackend() Backend { return unsupportedBackend{os: runtime.GOOS} }
