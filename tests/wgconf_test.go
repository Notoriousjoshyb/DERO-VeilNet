package veilnettest

import (
	"strings"
	"testing"

	"github.com/dero-veilnet/veilnet/tests/ref"
)

func TestWgConfRendersInterfaceAndPeer(t *testing.T) {
	out, err := ref.RenderWgConf(goodConfig())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"[Interface]", "PrivateKey = ", "Address = 10.200.0.2/32", "DNS = 10.200.0.1",
		"[Peer]", "PublicKey = ", "Endpoint = 203.0.113.10:51820",
		"AllowedIPs = 0.0.0.0/0", "PersistentKeepalive = 25",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("rendered conf missing %q:\n%s", want, out)
		}
	}
}

func TestWgConfOmitsZeroKeepalive(t *testing.T) {
	cfg := goodConfig()
	cfg.Peers[0].Keepalive = 0
	out, err := ref.RenderWgConf(cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(out, "PersistentKeepalive") {
		t.Fatal("zero keepalive must omit the line")
	}
}

func TestWgConfRejectsInvalid(t *testing.T) {
	bad := goodConfig()
	bad.Peers[0].AllowedIPs = nil
	if _, err := ref.RenderWgConf(bad); err == nil {
		t.Fatal("missing AllowedIPs accepted")
	}
	empty := goodConfig()
	empty.Peers = nil
	if _, err := ref.RenderWgConf(empty); err == nil {
		t.Fatal("peerless config accepted")
	}
}

func TestWgConfEndpointRoundTrip(t *testing.T) {
	cfg := goodConfig()
	cfg.Peers = append(cfg.Peers, ref.Peer{
		PublicKey:  strings.Repeat("p", 44),
		Endpoint:   "192.0.2.9:51820",
		AllowedIPs: []string{"0.0.0.0/0"},
		Keepalive:  25,
	})
	out, err := ref.RenderWgConf(cfg)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	eps, err := ref.ParseWgConfEndpoints(out)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(eps) != 2 || eps[0] != "203.0.113.10:51820" || eps[1] != "192.0.2.9:51820" {
		t.Fatalf("endpoints = %v", eps)
	}
}
