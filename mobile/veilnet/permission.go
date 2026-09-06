package veilnet

// OS VPN-permission and TUN handoff.
//
// A mobile app cannot open a TUN device itself. The OS owns it:
//
//   - Android: the host calls VpnService.prepare(), the user accepts the
//     system VPN dialog, then VpnService.Builder.establish() returns a
//     ParcelFileDescriptor. The host hands that fd here.
//   - iOS/macOS: the host runs a NEPacketTunnelProvider extension. The
//     provider owns the packet flow, so there is no integer fd; the host
//     declares the grant instead.
//
// Binding rule kept here: without a granted, live tunnel handle the
// library refuses to Start. A mobile client must never report a
// connection it cannot actually carry — that is the same silent-leak
// failure the desktop client refuses.
//
// Every function returns the standard string envelope so gomobile can
// bind it on both platforms.

import (
	"errors"
	"strings"
	"sync"
)

// Tunnel providers, as reported to the host.
const (
	// ProviderAndroid uses VpnService + an integer file descriptor.
	ProviderAndroid = "android-vpnservice"
	// ProviderApple uses NEPacketTunnelProvider; no fd crosses the API.
	ProviderApple = "apple-packettunnel"
)

// permission is the process-wide VPN grant state.
var permission = struct {
	sync.Mutex
	provider string
	granted  bool
	fd       int
	reason   string
}{fd: -1}

// permissionInfo is the JSON the host receives from RequestPermission.
type permissionInfo struct {
	Provider string `json:"provider"`
	Granted  bool   `json:"granted"`
	// HasTunnel is true when a usable tunnel handle is held: a live fd on
	// Android, or a declared provider grant on Apple.
	HasTunnel bool `json:"has_tunnel"`
	// FD is the Android descriptor, or -1 when none is held.
	FD int `json:"fd"`
	// Steps tells the host exactly what to do next, in order.
	Steps []string `json:"steps"`
	// Reason explains a missing grant.
	Reason string `json:"reason,omitempty"`
}

// androidSteps and appleSteps are the host-side call sequences. They are
// documentation the host can render, not instructions this library runs.
var androidSteps = []string{
	"Call VpnService.prepare(context); if it returns an Intent, start it and wait for RESULT_OK.",
	"Build the tunnel: VpnService.Builder().addAddress(...).addDnsServer(...).addRoute(\"0.0.0.0\", 0).establish().",
	"Pass the descriptor: SetTunnelFD(pfd.detachFd()).",
	"Then call Start(nodeId).",
	"On stop: call Stop(), then ClearTunnel(), then close the descriptor.",
}

var appleSteps = []string{
	"Ship a NEPacketTunnelProvider network extension with the packet-tunnel entitlement.",
	"Install/enable the NETunnelProviderManager profile; the user accepts the system prompt.",
	"Inside startTunnel(options:), call GrantTunnel(\"apple-packettunnel\").",
	"Then call Start(nodeId).",
	"On stopTunnel(with:), call Stop(), then ClearTunnel().",
}

func stepsFor(provider string) []string {
	if provider == ProviderApple {
		return appleSteps
	}
	return androidSteps
}

// RequestPermission reports what the host must do to grant VPN
// permission, and whether a usable tunnel handle is already held.
// Pass "android-vpnservice" or "apple-packettunnel"; an empty provider
// defaults to Android.
//
// This function never triggers an OS prompt: only the host app can, from
// its own UI thread. It returns the steps to follow.
func RequestPermission(provider string) string {
	provider = normalizeProvider(provider)
	permission.Lock()
	defer permission.Unlock()
	if permission.provider == "" {
		permission.provider = provider
	}
	return ok(permissionInfo{
		Provider:  provider,
		Granted:   permission.granted,
		HasTunnel: hasTunnelLocked(),
		FD:        permission.fd,
		Steps:     stepsFor(provider),
		Reason:    permission.reason,
	})
}

// SetTunnelFD hands over the Android VpnService descriptor from
// VpnService.Builder.establish(). The library does not own the
// descriptor's lifetime: the host closes it after ClearTunnel.
//
// A negative descriptor is rejected — that is what a failed establish()
// returns, and treating it as valid would mean claiming a tunnel that
// does not exist.
func SetTunnelFD(fd int) string {
	if fd < 0 {
		return fail("invalid tunnel descriptor " + itoa(fd) +
			": VpnService.Builder.establish() failed or permission was refused")
	}
	permission.Lock()
	defer permission.Unlock()
	permission.provider = ProviderAndroid
	permission.fd = fd
	permission.granted = true
	permission.reason = ""
	return ok(permissionInfo{
		Provider: ProviderAndroid, Granted: true, HasTunnel: true, FD: fd,
		Steps: []string{"Tunnel descriptor accepted. Call Start(nodeId)."},
	})
}

// GrantTunnel records an Apple NEPacketTunnelProvider grant, where the
// provider owns the packet flow and no descriptor crosses this API.
func GrantTunnel(provider string) string {
	provider = normalizeProvider(provider)
	if provider == ProviderAndroid {
		return fail("android must hand over a descriptor: call SetTunnelFD(fd) instead")
	}
	permission.Lock()
	defer permission.Unlock()
	permission.provider = provider
	permission.granted = true
	permission.fd = -1
	permission.reason = ""
	return ok(permissionInfo{
		Provider: provider, Granted: true, HasTunnel: true, FD: -1,
		Steps: []string{"Provider grant accepted. Call Start(nodeId)."},
	})
}

// ClearTunnel drops the grant and forgets the descriptor. Call it after
// Stop, before closing the descriptor on Android. Idempotent.
func ClearTunnel() string {
	permission.Lock()
	defer permission.Unlock()
	prov := permission.provider
	permission.granted = false
	permission.fd = -1
	permission.reason = "tunnel handle released by the host"
	return ok(permissionInfo{
		Provider: prov, Granted: false, HasTunnel: false, FD: -1,
		Steps:  stepsFor(prov),
		Reason: permission.reason,
	})
}

// PermissionStatus reports the current grant without changing it.
func PermissionStatus() string {
	permission.Lock()
	defer permission.Unlock()
	prov := permission.provider
	if prov == "" {
		prov = ProviderAndroid
	}
	return ok(permissionInfo{
		Provider:  prov,
		Granted:   permission.granted,
		HasTunnel: hasTunnelLocked(),
		FD:        permission.fd,
		Steps:     stepsFor(prov),
		Reason:    permission.reason,
	})
}

// errNoTunnelPermission is returned by Start when the OS has not handed
// over a tunnel. It names the exact next call, never a bare failure.
var errNoTunnelPermission = errors.New(
	"no OS VPN permission: call RequestPermission(provider), follow the steps, " +
		"then SetTunnelFD(fd) on Android or GrantTunnel(\"apple-packettunnel\") on iOS")

// requireTunnel gates Start. Demo mode is exempt: it carries no real
// traffic, so it needs no OS tunnel, and it is badged as demo.
func requireTunnel(demo bool) error {
	if demo {
		return nil
	}
	permission.Lock()
	defer permission.Unlock()
	if !hasTunnelLocked() {
		return errNoTunnelPermission
	}
	return nil
}

// hasTunnelLocked reports a usable tunnel handle. Callers hold the lock.
func hasTunnelLocked() bool {
	if !permission.granted {
		return false
	}
	if permission.provider == ProviderApple {
		return true
	}
	return permission.fd >= 0
}

func normalizeProvider(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", ProviderAndroid, "android", "vpnservice":
		return ProviderAndroid
	case ProviderApple, "apple", "ios", "macos", "packettunnel", "nepackettunnelprovider":
		return ProviderApple
	default:
		return ProviderAndroid
	}
}

// itoa avoids importing strconv for one call in an error string.
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// resetPermissionForTest clears grant state (Go tests only).
func resetPermissionForTest() {
	permission.Lock()
	defer permission.Unlock()
	permission.provider = ""
	permission.granted = false
	permission.fd = -1
	permission.reason = ""
}
