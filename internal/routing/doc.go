// Package routing manages secure OS routes for VeilNet tunnels through
// per-OS backends selected in select_windows.go / select_linux.go /
// select_darwin.go:
//
//	netsh (Windows), `ip route` (Linux), BSD `route` (macOS).
//
// See route.go and docs/PLATFORM.md.
package routing
