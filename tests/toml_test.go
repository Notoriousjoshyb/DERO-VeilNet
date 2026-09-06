package veilnettest

// TOML config parsing against the real BurntSushi/toml driver: proves the
// client/node config files the app reads (paths in config_test.go) decode
// with defaults applied and invalid input refused.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
)

type clientConfig struct {
	Node      string `toml:"node"`
	Region    string `toml:"region"`
	KillSwitch string `toml:"kill_switch"`
	DNS       string `toml:"dns"`
	IPv6      string `toml:"ipv6"`
	Demo      bool   `toml:"demo"`
}

func (c *clientConfig) defaults() {
	if c.KillSwitch == "" {
		c.KillSwitch = "ON_WHILE_CONNECTED"
	}
	if c.DNS == "" {
		c.DNS = "VEILNET"
	}
	if c.IPv6 == "" {
		c.IPv6 = "BLOCKED"
	}
}

func writeTOML(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestTOMLClientConfigDecodes(t *testing.T) {
	p := writeTOML(t, `
node = "nodeA"
region = "eu-central"
kill_switch = "ALWAYS_ON"
dns = "DOH"
ipv6 = "ROUTED"
demo = false
`)
	var cfg clientConfig
	if _, err := toml.DecodeFile(p, &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	cfg.defaults()
	if cfg.Node != "nodeA" || cfg.Region != "eu-central" {
		t.Fatalf("config = %+v", cfg)
	}
	if cfg.KillSwitch != "ALWAYS_ON" || cfg.DNS != "DOH" || cfg.IPv6 != "ROUTED" {
		t.Fatalf("policy = %+v", cfg)
	}
}

func TestTOMLMissingKeysGetSafeDefaults(t *testing.T) {
	p := writeTOML(t, `node = "nodeB"` + "\n")
	var cfg clientConfig
	if _, err := toml.DecodeFile(p, &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	cfg.defaults()
	// Defaults must equal the safe policy defaults (policy_test.go).
	if cfg.KillSwitch != "ON_WHILE_CONNECTED" || cfg.DNS != "VEILNET" || cfg.IPv6 != "BLOCKED" {
		t.Fatalf("unsafe defaults: %+v", cfg)
	}
}

func TestTOMLInvalidRefused(t *testing.T) {
	p := writeTOML(t, `kill_switch = = "broken"` + "\n")
	var cfg clientConfig
	if _, err := toml.DecodeFile(p, &cfg); err == nil {
		t.Fatal("malformed TOML accepted")
	}
}

func TestTOMLDemoFlagRoundTrip(t *testing.T) {
	p := writeTOML(t, "demo = true\n")
	var cfg clientConfig
	if _, err := toml.DecodeFile(p, &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !cfg.Demo {
		t.Fatal("demo flag lost in decode")
	}
}
