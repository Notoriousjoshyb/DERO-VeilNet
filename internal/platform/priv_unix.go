//go:build !windows

package platform

import "os"

// IsAdmin reports whether the process runs as root (euid 0).
func IsAdmin() bool { return os.Geteuid() == 0 }

// PrivilegeHint names the fix when elevation is missing.
func PrivilegeHint() string {
	if CurrentOS() == Darwin {
		return "re-run with sudo, or install the launchd daemon: sudo cp net.veilnet.daemon.plist /Library/LaunchDaemons/ && sudo launchctl load /Library/LaunchDaemons/net.veilnet.daemon.plist"
	}
	return "re-run with sudo, or install the systemd unit: sudo systemctl enable --now veilnet"
}
