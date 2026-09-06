package veilnet

import (
	"encoding/json"
	"strings"
	"testing"
)

func decodeEnvelope(t *testing.T, raw string) (envelope, permissionInfo) {
	t.Helper()
	var env envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("envelope decode: %v (%s)", err, raw)
	}
	var info permissionInfo
	if env.Data != "" {
		if err := json.Unmarshal([]byte(env.Data), &info); err != nil {
			t.Fatalf("data decode: %v (%s)", err, env.Data)
		}
	}
	return env, info
}

// The host is told exactly what to call, per platform, before any grant.
func TestRequestPermissionNamesTheSteps(t *testing.T) {
	resetPermissionForTest()

	_, android := decodeEnvelope(t, RequestPermission("android"))
	if android.Provider != ProviderAndroid || android.Granted || android.HasTunnel {
		t.Fatalf("android info = %+v, want ungranted android", android)
	}
	if len(android.Steps) == 0 || !strings.Contains(strings.Join(android.Steps, " "), "VpnService.prepare") {
		t.Fatalf("android steps must name VpnService.prepare, got %v", android.Steps)
	}
	if android.FD != -1 {
		t.Fatalf("fd = %d, want -1 before any grant", android.FD)
	}

	_, apple := decodeEnvelope(t, RequestPermission("ios"))
	if apple.Provider != ProviderApple {
		t.Fatalf("provider = %q, want %q", apple.Provider, ProviderApple)
	}
	if !strings.Contains(strings.Join(apple.Steps, " "), "NEPacketTunnelProvider") {
		t.Fatalf("apple steps must name NEPacketTunnelProvider, got %v", apple.Steps)
	}
}

// A failed establish() returns a negative fd. Accepting it would mean
// claiming a tunnel that does not exist.
func TestSetTunnelFDRejectsNegative(t *testing.T) {
	resetPermissionForTest()
	env, _ := decodeEnvelope(t, SetTunnelFD(-1))
	if env.OK {
		t.Fatal("a negative descriptor must be refused")
	}
	if !strings.Contains(env.Error, "establish()") {
		t.Fatalf("error must name the cause, got %q", env.Error)
	}
	if err := requireTunnel(false); err == nil {
		t.Fatal("no tunnel must remain after a refused descriptor")
	}
}

func TestAndroidGrantLifecycle(t *testing.T) {
	resetPermissionForTest()

	env, info := decodeEnvelope(t, SetTunnelFD(42))
	if !env.OK || !info.HasTunnel || info.FD != 42 {
		t.Fatalf("grant = %+v (ok=%v), want fd 42 held", info, env.OK)
	}
	if err := requireTunnel(false); err != nil {
		t.Fatalf("Start must be allowed after a valid descriptor: %v", err)
	}

	_, cleared := decodeEnvelope(t, ClearTunnel())
	if cleared.HasTunnel || cleared.FD != -1 || cleared.Granted {
		t.Fatalf("after ClearTunnel = %+v, want nothing held", cleared)
	}
	if err := requireTunnel(false); err == nil {
		t.Fatal("Start must be refused again once the tunnel is released")
	}
	// Idempotent.
	if env, _ := decodeEnvelope(t, ClearTunnel()); !env.OK {
		t.Fatal("ClearTunnel must be idempotent")
	}
}

func TestApplyGrantNeedsNoDescriptor(t *testing.T) {
	resetPermissionForTest()

	env, info := decodeEnvelope(t, GrantTunnel(ProviderApple))
	if !env.OK || !info.HasTunnel || info.FD != -1 {
		t.Fatalf("apple grant = %+v (ok=%v), want held with no fd", info, env.OK)
	}
	if err := requireTunnel(false); err != nil {
		t.Fatalf("Start must be allowed after an apple grant: %v", err)
	}

	// Android may not take this shortcut: it must hand over a descriptor.
	resetPermissionForTest()
	env, _ = decodeEnvelope(t, GrantTunnel("android"))
	if env.OK {
		t.Fatal("android must not be grantable without a descriptor")
	}
	if !strings.Contains(env.Error, "SetTunnelFD") {
		t.Fatalf("error must name the right call, got %q", env.Error)
	}
}

// Start must refuse without an OS tunnel, and the error must say what to
// call next rather than failing bare.
func TestStartRefusedWithoutTunnelPermission(t *testing.T) {
	resetPermissionForTest()
	if err := requireTunnel(false); err == nil {
		t.Fatal("Start must be gated on OS VPN permission")
	} else if !strings.Contains(err.Error(), "SetTunnelFD") ||
		!strings.Contains(err.Error(), "GrantTunnel") {
		t.Fatalf("error must name both platform calls, got %q", err)
	}
	// Demo carries no real traffic, so it needs no OS tunnel.
	if err := requireTunnel(true); err != nil {
		t.Fatalf("demo must not need an OS tunnel: %v", err)
	}
}
