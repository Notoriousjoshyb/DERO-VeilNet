//go:build windows

package tunnel

import (
	"os/exec"
	"strings"
)

// probeKernel reports whether the WireGuardNT kernel driver path is
// usable, falling back to wintun userspace otherwise.
//
// Detection queries the Service Control Manager for the WireGuardNT
// driver service (`sc query WireGuardNT`). State RUNNING means the
// kernel driver is live; any other outcome (service missing, stopped,
// access denied) returns available=false with a detail naming the
// cause so the backend-selection log explains the wintun fallback.
func probeKernel() (available bool, detail string) {
	out, err := exec.Command("sc", "query", "WireGuardNT").CombinedOutput()
	if err != nil {
		return false, "WireGuardNT service not usable (`sc query WireGuardNT`: " + oneLine(out, err) + "); using wintun userspace"
	}
	upper := strings.ToUpper(string(out))
	if strings.Contains(upper, "RUNNING") {
		return true, "WireGuardNT service RUNNING"
	}
	return false, "WireGuardNT service present but not RUNNING; using wintun userspace"
}

func oneLine(out []byte, err error) string {
	s := strings.TrimSpace(string(out))
	if s == "" {
		return err.Error()
	}
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	// Collapse newlines for a single log line.
	return strings.Join(strings.Fields(s), " ")
}
