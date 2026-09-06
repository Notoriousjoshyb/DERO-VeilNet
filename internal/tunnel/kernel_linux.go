//go:build linux

package tunnel

import (
	"fmt"
	"os"
	"os/exec"
)

// probeKernel reports whether a kernel WireGuard data plane is usable.
//
// Probe order (side-effect free on the host):
//  1. /sys/module/wireguard present -> kernel module loaded.
//  2. Otherwise, netns-safe dry run: `ip link add <tmp> type wireguard`
//     with an immediately-deferred delete. A unique interface name
//     (PID-suffixed) guarantees no collision with real interfaces, and
//     the delete runs even on failure paths. No address is assigned and
//     the interface is never set up, so host networking is untouched.
//
// Missing `ip` binary or any failure returns available=false with a
// detail string naming the cause; the caller falls back to userspace.
func probeKernel() (available bool, detail string) {
	if fi, err := os.Stat("/sys/module/wireguard"); err == nil && fi.IsDir() {
		return true, "kernel module loaded (/sys/module/wireguard)"
	}
	ipBin, err := exec.LookPath("ip")
	if err != nil {
		return false, "no kernel module (/sys/module/wireguard absent) and no `ip` tool for dry-run probe"
	}
	ifName := fmt.Sprintf("veilnet-probe%d", os.Getpid())
	add := exec.Command(ipBin, "link", "add", ifName, "type", "wireguard")
	if out, err := add.CombinedOutput(); err != nil {
		return false, fmt.Sprintf("kernel dry-run `ip link add type wireguard` failed: %v (%s)", err, trimOut(out))
	}
	// Best-effort cleanup: the probe interface must never linger.
	del := exec.Command(ipBin, "link", "del", ifName)
	if out, err := del.CombinedOutput(); err != nil {
		return true, fmt.Sprintf("kernel usable but probe cleanup needs attention: %v (%s)", err, trimOut(out))
	}
	return true, "kernel usable (dry-run `ip link add type wireguard` succeeded, probe removed)"
}

func trimOut(b []byte) string {
	s := string(b)
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	if s == "" {
		return "no output"
	}
	return s
}
