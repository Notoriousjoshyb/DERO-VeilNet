// Shared backend-kind reporting for the tunnel engine.
//
// The engine selects exactly one live backend at Start: "kernel" (an
// OS-managed WireGuard interface configured via wgctrl) or "userspace"
// (embedded wireguard-go over a TUN). The selected kind and a short
// human-readable detail are recorded for Status().Detail and logs.
//
// OS capability probes live in kernel_linux.go / kernel_windows.go /
// kernel_other.go; this file holds only shared types.
package tunnel

// BackendKind names the active data-plane backend.
type BackendKind string

// Backend kinds reported in Status().Detail and the start log.
const (
	// BackendKernel configures a pre-existing OS WireGuard interface
	// (Linux kernel module, WireGuardNT) via wgctrl.
	BackendKernel BackendKind = "kernel"
	// BackendUserspace runs embedded wireguard-go over a TUN device
	// (Wintun on Windows, utun elsewhere, in-memory in tests).
	BackendUserspace BackendKind = "userspace"
)

// backendReport is the recorded backend decision.
type backendReport struct {
	kind   BackendKind
	detail string
}

// String renders "kind (detail)" for logs and Status().Detail.
func (r backendReport) String() string {
	if r.detail == "" {
		return string(r.kind)
	}
	return string(r.kind) + " (" + r.detail + ")"
}
