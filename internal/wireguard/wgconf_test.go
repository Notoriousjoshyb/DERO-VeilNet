package wireguard

import (
	"strings"
	"testing"
)

func testConfig() Config {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		panic(err)
	}
	return Config{
		PrivateKey: priv,
		ListenPort: 51820,
		Addresses:  []string{"10.7.0.2/32"},
		DNS:        []string{"10.7.0.1"},
		Peers: []Peer{{
			PublicKey:  pub,
			Endpoint:   "203.0.113.7:51820",
			AllowedIPs: []string{"0.0.0.0/0", "::/0"},
			Keepalive:  25,
		}},
	}
}

func TestKeypairRoundtrip(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != 44 || len(pub) != 44 {
		t.Fatalf("key lengths = %d/%d, want 44/44", len(priv), len(pub))
	}
	derived, err := PublicKeyFor(priv)
	if err != nil {
		t.Fatal(err)
	}
	if derived != pub {
		t.Fatal("derived public key mismatches generated one")
	}
	if _, err := PublicKeyFor("not-a-key"); err == nil {
		t.Fatal("bad key must fail")
	}
	if p1, _, _ := GenerateKeypair(); p1 == priv {
		t.Fatal("keys must differ")
	}
}

func TestINIRoundtrip(t *testing.T) {
	cfg := testConfig()
	ini := GenerateINI(cfg)
	for _, want := range []string{"[Interface]", "[Peer]", "PrivateKey", "PublicKey",
		"203.0.113.7:51820", "PersistentKeepalive = 25", "ListenPort = 51820"} {
		if !strings.Contains(ini, want) {
			t.Fatalf("INI missing %q:\n%s", want, ini)
		}
	}
	back, err := ParseINI(ini)
	if err != nil {
		t.Fatal(err)
	}
	if back.PrivateKey != cfg.PrivateKey || back.ListenPort != 51820 || back.MTU != 0 {
		t.Fatalf("roundtrip mismatch: %+v", back)
	}
	if len(back.Peers) != 1 || back.Peers[0].Endpoint != "203.0.113.7:51820" ||
		back.Peers[0].Keepalive != 25 || len(back.Peers[0].AllowedIPs) != 2 {
		t.Fatalf("peer roundtrip mismatch: %+v", back.Peers)
	}
	if _, err := ParseINI("[Interface]\nAddress = 10.0.0.1/32\n"); err == nil {
		t.Fatal("missing private key must fail")
	}
}

func TestValidate(t *testing.T) {
	if err := Validate(testConfig()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := testConfig()
	bad.Peers[0].Endpoint = "no-port"
	if err := Validate(bad); err == nil {
		t.Fatal("bad endpoint accepted")
	}
	empty := testConfig()
	empty.Peers = nil
	if err := Validate(empty); err == nil {
		t.Fatal("peerless config accepted")
	}
}

func TestIPCExcludesAddresses(t *testing.T) {
	ipc, err := ToIPC(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"private_key=", "listen_port=51820", "public_key=",
		"endpoint=203.0.113.7:51820", "allowed_ip=0.0.0.0/0",
		"persistent_keepalive_interval=25"} {
		if !strings.Contains(ipc, want) {
			t.Fatalf("IPC missing %q:\n%s", want, ipc)
		}
	}
	if strings.Contains(ipc, "10.7.0") {
		t.Fatalf("addresses/DNS must not enter device IPC:\n%s", ipc)
	}
}

func TestParseIPCDump(t *testing.T) {
	dump := "private_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\n" +
		"listen_port=51820\n" +
		"public_key=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=\n" +
		"endpoint=127.0.0.1:1111\nrx_bytes=1200\ntx_bytes=3400\n" +
		"last_handshake_time_sec=1700000000\nlast_handshake_time_nsec=0\n" +
		"allowed_ip=10.7.0.2/32\npersistent_keepalive_interval=25\n"
	peers := ParseIPCDump(dump)
	if len(peers) != 1 {
		t.Fatalf("peers = %d", len(peers))
	}
	rx, tx, hs := AggregateStats(peers)
	if rx != 1200 || tx != 3400 {
		t.Fatalf("rx/tx = %d/%d", rx, tx)
	}
	if hs.Unix() != 1700000000 {
		t.Fatalf("handshake = %v", hs)
	}
	rx0, tx0, hs0 := AggregateStats(nil)
	if rx0 != 0 || tx0 != 0 || !hs0.IsZero() {
		t.Fatal("empty aggregate must be zero")
	}
}
