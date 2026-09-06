package veilnettest

import (
	"testing"
	"time"

	"github.com/dero-veilnet/veilnet/tests/ref"
)

func goodConfig() ref.WireGuardConfig {
	return ref.WireGuardConfig{
		PrivateKey: "c2VjcmV0LWtleS1mb3ItdGVzdGluZy1vbmx5LTAwMDAwMDA=",
		Addresses:  []string{"10.200.0.2/32"},
		DNS:        []string{"10.200.0.1"},
		Peers: []ref.Peer{{
			PublicKey:  "dGVzdC1ub2RlLXB1YmxpYy1rZXktZm9yLXRlc3Rpbmctb25seQ==",
			Endpoint:   "203.0.113.10:51820",
			AllowedIPs: []string{"0.0.0.0/0"},
			Keepalive:  25,
		}},
	}
}

func TestEngineStartReachesUpAfterHandshake(t *testing.T) {
	e := ref.NewFakeEngine()
	if got := e.Status().State; got != ref.Down {
		t.Fatalf("initial state = %s, want DOWN", got)
	}
	if err := e.Start(goodConfig()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := e.Status().State; got != ref.Connecting {
		t.Fatalf("after Start = %s, want CONNECTING", got)
	}
	before := time.Now().UTC()
	e.Handshake()
	st := e.Status()
	if st.State != ref.Up {
		t.Fatalf("after Handshake = %s, want UP", st.State)
	}
	if st.LastHandshake.Before(before) {
		t.Fatal("LastHandshake not recorded at handshake time")
	}
	if st.Endpoint != "203.0.113.10:51820" {
		t.Fatalf("Endpoint = %q", st.Endpoint)
	}
}

func TestEngineRejectsBadConfigAndMarksFailed(t *testing.T) {
	e := ref.NewFakeEngine()
	bad := goodConfig()
	bad.PrivateKey = ""
	if err := e.Start(bad); err == nil {
		t.Fatal("Start with empty key must fail")
	}
	if got := e.Status().State; got != ref.Failed {
		t.Fatalf("state = %s, want FAILED", got)
	}
}

func TestEngineDoubleStartAndDoubleStop(t *testing.T) {
	e := ref.NewFakeEngine()
	if err := e.Start(goodConfig()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := e.Start(goodConfig()); err == nil {
		t.Fatal("second Start must fail")
	}
	e.Handshake()
	if err := e.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := e.Status().State; got != ref.Down {
		t.Fatalf("after Stop = %s, want DOWN", got)
	}
	if err := e.Stop(); err == nil {
		t.Fatal("second Stop must fail")
	}
}

func TestEngineStatisticsAccumulate(t *testing.T) {
	e := ref.NewFakeEngine()
	if err := e.Start(goodConfig()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	e.Handshake()
	e.AddTraffic(1000, 500)
	e.AddTraffic(2000, 1500)
	s := e.Statistics()
	if s.RxBytes != 3000 || s.TxBytes != 2000 {
		t.Fatalf("Stats = %+v, want Rx 3000 Tx 2000", s)
	}
	if s.LastHandshake.IsZero() {
		t.Fatal("LastHandshake missing from stats")
	}
}

func TestEngineApplyConfigurationWhileUp(t *testing.T) {
	e := ref.NewFakeEngine()
	if err := e.Start(goodConfig()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	e.Handshake()
	cfg := goodConfig()
	cfg.Peers[0].Endpoint = "198.51.100.7:51820"
	if err := e.ApplyConfiguration(cfg); err != nil {
		t.Fatalf("ApplyConfiguration: %v", err)
	}
	if got := e.Status().Endpoint; got != "198.51.100.7:51820" {
		t.Fatalf("Endpoint = %q after apply", got)
	}
	if got := e.Status().State; got != ref.Up {
		t.Fatalf("state = %s, want UP preserved", got)
	}
}

func TestEngineRotateEndpoint(t *testing.T) {
	e := ref.NewFakeEngine()
	cfg := goodConfig()
	cfg.Peers = append(cfg.Peers, ref.Peer{
		PublicKey:  "c2Vjb25kLXBlZXItcHViaWMta2V5LWZvci10ZXN0aW5nLW9ubHk=",
		Endpoint:   "192.0.2.9:51820",
		AllowedIPs: []string{"0.0.0.0/0"},
		Keepalive:  25,
	})
	if err := e.Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	e.Handshake()
	if err := e.RotateEndpoint("192.0.2.9:51820"); err != nil {
		t.Fatalf("RotateEndpoint: %v", err)
	}
	if got := e.Status().Endpoint; got != "192.0.2.9:51820" {
		t.Fatalf("Endpoint = %q after rotate", got)
	}
	if err := e.RotateEndpoint("10.9.9.9:1"); err == nil {
		t.Fatal("rotate to unknown endpoint must fail")
	}
}

func TestEngineReconnectAfterInjectedFailure(t *testing.T) {
	e := ref.NewFakeEngine()
	if err := e.Start(goodConfig()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	e.Handshake()
	if err := e.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	e.InjectFailure()
	if err := e.Start(goodConfig()); err == nil {
		t.Fatal("injected failure must surface")
	}
	if got := e.Status().State; got != ref.Failed {
		t.Fatalf("state = %s, want FAILED", got)
	}
	if err := e.Start(goodConfig()); err != nil {
		t.Fatalf("reconnect Start: %v", err)
	}
	e.Handshake()
	if got := e.Status().State; got != ref.Up {
		t.Fatalf("after reconnect = %s, want UP", got)
	}
	if n := e.HandshakeCount(); n != 2 {
		t.Fatalf("handshakes = %d, want 2", n)
	}
}
