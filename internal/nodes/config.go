package nodes

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Versioning for heartbeat / status display.
const (
	Version         = "0.1.0"
	ProtocolVersion = 1
)

// NodeType distinguishes exit traffic from relay (multihop middle)
// traffic. It is always explicit — never inferred.
type NodeType string

const (
	NodeTypeExit  NodeType = "EXIT"
	NodeTypeRelay NodeType = "RELAY"
)

// Config is the node operator configuration, stored as TOML at
// ~/.veilnet-node/config.toml.
type Config struct {
	NodeID   string   `toml:"node_id"`
	NodeType NodeType `toml:"node_type"`

	Region  string `toml:"region"`
	Country string `toml:"country"`
	City    string `toml:"city"`

	MaxClients        int     `toml:"max_clients"`
	BandwidthDownMbps int     `toml:"bandwidth_down_mbps"`
	BandwidthUpMbps   int     `toml:"bandwidth_up_mbps"`
	PricePerHourDero  float64 `toml:"price_per_hour_dero"`
	AcceptNew         bool    `toml:"accept_new"`
	PublicEndpoint    string  `toml:"public_endpoint"`

	DeroAddress string  `toml:"dero_address"`
	BondDero    float64 `toml:"bond_dero"`

	HeartbeatIntervalSec int    `toml:"heartbeat_interval_sec"`
	MgmtBind             string `toml:"mgmt_bind"`
	// AllowRemote permits the control API to bind/serve non-loopback
	// addresses. Default false: unreachable from non-loopback.
	AllowRemote bool `toml:"allow_remote"`

	WGInterface  string `toml:"wg_interface"`
	WGListenPort int    `toml:"wg_listen_port"`
	WGAddress    string `toml:"wg_address"`
	// WGPrivateKey is base64 (never published, never put on-chain).
	WGPrivateKey string `toml:"wg_private_key"`
	CGNAT        string `toml:"cgnat_cidr"`

	AbuseContact string `toml:"abuse_contact"`
	Jurisdiction string `toml:"jurisdiction"`

	AllowedPorts []int `toml:"allowed_ports"`
	DeniedPorts  []int `toml:"denied_ports"`
	// DefaultAllow=true means all outbound ports allowed except denied.
	DefaultAllow bool `toml:"default_allow"`

	RateLimitKbps int `toml:"rate_limit_kbps"`
	RateBurstKB   int `toml:"rate_burst_kb"`

	MaxSessionMinutes int  `toml:"max_session_minutes"`
	EmergencyDisable  bool `toml:"emergency_disable"`

	// DevAllowAny permits unsigned dev tokens. Explicit opt-in only;
	// the daemon logs a loud warning while enabled.
	DevAllowAny bool `toml:"dev_allow_any"`
}

// DefaultConfig returns sane local defaults.
func DefaultConfig() *Config {
	return &Config{
		NodeType:             NodeTypeExit,
		Region:               "local",
		Country:              "dev",
		City:                 "localhost",
		MaxClients:           50,
		BandwidthDownMbps:    100,
		BandwidthUpMbps:      100,
		PricePerHourDero:     0.01,
		AcceptNew:            true,
		HeartbeatIntervalSec: 60,
		MgmtBind:             "127.0.0.1:18081",
		WGInterface:          "veilnet0",
		WGListenPort:         51820,
		WGAddress:            "100.64.0.1",
		CGNAT:                "100.64.0.0/10",
		DefaultAllow:         true,
		DeniedPorts:          []int{25},
		RateLimitKbps:        0,
		RateBurstKB:          0,
		MaxSessionMinutes:    480,
	}
}

// DefaultDir returns ~/.veilnet-node.
func DefaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".veilnet-node"
	}
	return filepath.Join(home, ".veilnet-node")
}

// DefaultPath returns the default config file path.
func DefaultPath() string { return filepath.Join(DefaultDir(), "config.toml") }

// DefaultDBPath returns the default sqlite path.
func DefaultDBPath() string { return filepath.Join(DefaultDir(), "clients.db") }

// MgmtTokenPath returns the mgmt bearer-token file path.
func MgmtTokenPath() string { return filepath.Join(DefaultDir(), "mgmt.token") }

// ResolvePath maps "" to the default path.
func ResolvePath(p string) string {
	if p == "" {
		return DefaultPath()
	}
	return p
}

// Load reads a TOML config file.
func Load(path string) (*Config, error) {
	path = ResolvePath(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("nodes: read config %s: %w", path, err)
	}
	cfg := DefaultConfig()
	md, err := toml.Decode(string(data), cfg)
	if err != nil {
		return nil, fmt.Errorf("nodes: parse config %s: %w", path, err)
	}
	for _, key := range md.Undecoded() {
		_ = key
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Save writes the config as TOML (0600: contains a private key).
func (c *Config) Save(path string) error {
	path = ResolvePath(path)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(c)
}

// Validate checks operator-facing invariants.
func (c *Config) Validate() error {
	if c.NodeType != NodeTypeExit && c.NodeType != NodeTypeRelay {
		return fmt.Errorf("nodes: node_type must be EXIT or RELAY, got %q", c.NodeType)
	}
	if c.MaxClients <= 0 || c.MaxClients > 10000 {
		return errors.New("nodes: max_clients must be 1..10000")
	}
	if _, _, err := net.ParseCIDR(c.CGNAT); err != nil {
		return fmt.Errorf("nodes: bad cgnat_cidr: %w", err)
	}
	if ip := net.ParseIP(c.WGAddress); ip == nil {
		return fmt.Errorf("nodes: bad wg_address %q", c.WGAddress)
	}
	if c.MgmtBind == "" {
		return errors.New("nodes: mgmt_bind required")
	}
	if _, _, err := net.SplitHostPort(c.MgmtBind); err != nil {
		return fmt.Errorf("nodes: bad mgmt_bind: %w", err)
	}
	if !c.AllowRemote && !isLoopbackBind(c.MgmtBind) {
		return errors.New("nodes: mgmt_bind is non-loopback but allow_remote=false (refusing: mgmt API must stay on 127.0.0.1 by default)")
	}
	if c.MaxSessionMinutes < 0 {
		return errors.New("nodes: max_session_minutes must be >= 0")
	}
	if c.RateLimitKbps < 0 || c.RateBurstKB < 0 {
		return errors.New("nodes: rate limits must be >= 0")
	}
	return nil
}

func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
