package transport

import (
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

func TestDirectIsRegisteredAndDefault(t *testing.T) {
	tr, err := Get("")
	if err != nil {
		t.Fatalf("empty name must resolve to direct: %v", err)
	}
	if tr.Name() != DirectName {
		t.Fatalf("default = %q, want %q", tr.Name(), DirectName)
	}
	if tr.Obfuscating() {
		t.Fatal("direct must never claim to obfuscate: it is plain UDP")
	}
	b, err := tr.NewBind("203.0.113.1:51820")
	if err != nil || b == nil {
		t.Fatalf("direct bind = %v, %v", b, err)
	}
}

// An unknown transport must fail loudly. Silently sending plain UDP
// while the user believes they have a bridge is worse than not starting.
func TestUnknownTransportNeverFallsBack(t *testing.T) {
	_, err := Get("obfs4")
	if err == nil {
		t.Fatal("an unregistered transport must be an error, not a fallback")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not available") || !strings.Contains(msg, DirectName) {
		t.Fatalf("error must name the problem and the available options, got %q", msg)
	}
	if Available("obfs4") {
		t.Fatal("Available must agree with Get")
	}
}

type fakeTransport struct{ name string }

func (f fakeTransport) Name() string                          { return f.name }
func (f fakeTransport) Description() string                   { return "test only" }
func (f fakeTransport) Obfuscating() bool                     { return true }
func (f fakeTransport) NewBind(string) (conn.Bind, error)     { return conn.NewDefaultBind(), nil }

func TestRegisterAndList(t *testing.T) {
	Register(fakeTransport{name: "test-bridge"})
	names := Names()
	found := false
	for _, n := range names {
		if n == "test-bridge" {
			found = true
		}
	}
	if !found {
		t.Fatalf("registered transport missing from %v", names)
	}
	tr, err := Get("TEST-BRIDGE") // names are case-insensitive
	if err != nil || tr.Name() != "test-bridge" {
		t.Fatalf("case-insensitive lookup failed: %v, %v", tr, err)
	}
}

func TestDuplicateRegistrationPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("registering a duplicate name must panic, not silently win")
		}
	}()
	Register(directTransport{})
}
