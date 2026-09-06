//go:build !linux && !windows

package tunnel

import "runtime"

// probeKernel on platforms without a dedicated probe (darwin and
// others) reports unavailable: the engine configures a pre-existing
// interface via wgctrl when one exists, otherwise uses the embedded
// userspace device. There is deliberately no OS-specific branching
// anywhere else: all platform queries stay in kernel_*.go.
func probeKernel() (available bool, detail string) {
	return false, "no kernel probe on " + runtime.GOOS + "; using userspace unless a pre-existing interface is configured"
}
