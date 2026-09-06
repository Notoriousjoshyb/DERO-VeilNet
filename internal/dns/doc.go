// Package dns manages DNS modes (VEILNET / CUSTOM / DOH /
// SYSTEM-explicit-only) and leak protection through per-OS backends
// selected in select_windows.go / select_linux.go / select_darwin.go:
//
//	netsh + NRPT (Windows), systemd-resolved with /etc/resolv.conf
//	fallback (Linux), networksetup with scutil fallback (macOS).
//
// See manager.go and docs/PLATFORM.md.
package dns
