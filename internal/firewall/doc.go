// Package firewall enforces the VeilNet kill switch (OFF /
// ON_WHILE_CONNECTED / ALWAYS_ON) through per-OS backends selected in
// select_windows.go / select_linux.go / select_darwin.go:
//
//	netsh advfirewall (Windows), nftables with iptables fallback (Linux),
//	pf anchor com.veilnet.killswitch (macOS).
//
// Fail-closed allow-list: handshake UDP + tunnel-local + DHCP + optional
// LAN pass, everything else drops. See killswitch.go and docs/PLATFORM.md.
package firewall
