// Package config loads and saves VeilNet TOML configuration.
//
// Client file: ~/.veilnet/config.toml
// Node file:   ~/.veilnet-node/config.toml
// Secrets are stored with 0600 permissions and never emitted to logs;
// use Redacted() before logging or displaying a config.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Kill switch modes (binding).
const (
	KillOff              = "OFF"
	KillWhileConnected   = "ON_WHILE_CONNECTED"
	KillAlwaysOn         = "ALWAYS_ON"
)

// DNS modes (binding). SYSTEM must be chosen explicitly, never by default.
const (
	DNSVeilnet = "VEILNET"
	DNSCustom  = "CUSTOM"
	DNSDoH     = "DOH"
	DNSSTem    = "SYSTEM"
)

// DNSModeSystem is the explicit-only system-resolver mode.
const DNSModeSystem = DNSSTem

// Selection policies for automatic node choice.
const (
	SelectFastest       = "FASTEST"
	SelectLowestLoad    = "LOWEST_LOAD"
	SelectLowestPrice   = "LOWEST_PRICE"
	SelectPrivacy       = "PRIVACY"
	SelectSpecificReg   = "SPECIFIC_REGION"
)

// NetworkConfig tunes timers, retries, and the entry transport.
type NetworkConfig struct {
	ProbeTimeoutSecs int    `toml:"probe_timeout_secs"`
	SelectPolicy     string `toml:"select_policy"`
	HandshakeTimeout int    `toml:"handshake_timeout_secs"`
	// Transport names the entry transport (internal/transport). Empty or
	// "direct" is plain UDP. An unregistered name is a startup error, not
	// a silent fallback: a client that believes it is bridged while
	// sending plain UDP is worse than one that refuses to start.
	Transport string `toml:"transport"`
}

// Cover-traffic shaping modes (internal/cover). OFF is the default: it
// trades real bandwidth for a narrow, specific gain, and the user makes
// that trade explicitly.
const (
	CoverOff      = "OFF"
	CoverPad      = "PAD"
	CoverConstant = "CONSTANT"
)

// CoverConfig configures measurable traffic shaping. PAD hides packet
// sizes only. CONSTANT hides size and timing while the tunnel keeps up
// with the rate. Neither defends against a global passive adversary —
// that is out of scope; see docs/THREAT_MODEL.md.
type CoverConfig struct {
	Mode string `toml:"mode"` // OFF|PAD|CONSTANT
	// CellSizeBytes and IntervalMs configure CONSTANT.
	CellSizeBytes int `toml:"cell_size_bytes"`
	IntervalMs    int `toml:"interval_ms"`
	// MaxOverhead caps wasted bandwidth as a ratio of real bytes
	// (0.5 = at most 50% cover). 0 means no cap.
	MaxOverhead float64 `toml:"max_overhead"`
}

// DeroConfig points at the DERO daemon/rpc used for control-plane ops.
// DERO never carries user traffic.
type DeroConfig struct {
	RPCEndpoint string `toml:"rpc_endpoint"`
	RPCUser     string `toml:"rpc_user"`
	RPCPassword string `toml:"rpc_password"` // secret
	Network     string `toml:"network"`      // mainnet|testnet|simulator
}

// Wallet connection modes. NONE keeps VeilNet wallet-less (demo and
// unpaid dev nodes still work). RPC talks to a local wallet JSON-RPC
// server. XSWD bridges to the user's wallet over the DERO
// wallet-to-dApp socket, where the wallet itself renders every prompt.
const (
	WalletModeNone = "NONE"
	WalletModeRPC  = "RPC"
	WalletModeXSWD = "XSWD"
)

// DefaultXSWDEndpoint is the documented DERO Stargate XSWD socket.
const DefaultXSWDEndpoint = "ws://127.0.0.1:44326/xswd"

// WalletConfig points at the wallet used for explicit payments.
// VeilNet never auto-spends; every payment needs explicit approval.
// Endpoint/User/Password apply to Mode RPC; XSWDEndpoint/AppName apply
// to Mode XSWD. Password is a secret and is masked by Redacted.
type WalletConfig struct {
	Mode         string `toml:"mode"` // NONE|RPC|XSWD
	Endpoint     string `toml:"endpoint"`
	Name         string `toml:"name"`
	User         string `toml:"user"`     // wallet --rpc-login user
	Password     string `toml:"password"` // secret
	XSWDEndpoint string `toml:"xswd_endpoint"`
	AppName      string `toml:"app_name"`
}

// DNSConfig selects resolver behavior. IPv6 is never silently leaked:
// when IPv6Upstream is false the client must block IPv6 while connected.
type DNSConfig struct {
	Mode         string   `toml:"mode"`
	Servers      []string `toml:"servers"`
	DoHURL       string   `toml:"doh_url"`
	IPv6Upstream bool     `toml:"ipv6_upstream"`
}

// MultihopConfig controls optional 2-hop circuits.
type MultihopConfig struct {
	Enabled       bool   `toml:"enabled"`
	EntryRegion   string `toml:"entry_region"`
	RotateMinutes int    `toml:"rotate_minutes"`
}

// PaymentsConfig caps explicit payment behavior.
type PaymentsConfig struct {
	MaxPerHourDero float64 `toml:"max_per_hour_dero"`
	Confirmations  int     `toml:"confirmations"`
	Currency       string  `toml:"currency"` // DERO
}

// LoggingConfig. Traffic content is never logged.
type LoggingConfig struct {
	Level string `toml:"level"` // debug|info|warn|error
	File  string `toml:"file"`
}

// ClientConfig is the full ~/.veilnet/config.toml document.
type ClientConfig struct {
	Network      NetworkConfig  `toml:"network"`
	Dero         DeroConfig     `toml:"dero"`
	Wallet       WalletConfig   `toml:"wallet"`
	DNS          DNSConfig      `toml:"dns"`
	KillSwitch   string         `toml:"killswitch"`
	AutoConnect  bool           `toml:"auto_connect"`
	Region       string         `toml:"region"`
	Multihop     MultihopConfig `toml:"multihop"`
	Cover        CoverConfig    `toml:"cover"`
	Payments     PaymentsConfig `toml:"payments"`
	Logging      LoggingConfig  `toml:"logging"`
}

// DefaultClientConfig returns safe defaults: kill switch on while
// connected, VeilNet DNS, no auto-spend, no silent leaks.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Network:     NetworkConfig{ProbeTimeoutSecs: 5, SelectPolicy: SelectFastest, HandshakeTimeout: 10},
		Dero:        DeroConfig{RPCEndpoint: "http://127.0.0.1:10102", Network: "mainnet"},
		Wallet: WalletConfig{
			Mode:         WalletModeNone,
			Endpoint:     "http://127.0.0.1:10103",
			XSWDEndpoint: DefaultXSWDEndpoint,
			AppName:      "VeilNet",
		},
		DNS:         DNSConfig{Mode: DNSVeilnet, IPv6Upstream: false},
		KillSwitch:  KillWhileConnected,
		AutoConnect: false,
		Multihop:    MultihopConfig{Enabled: false, RotateMinutes: 30},
		Cover:       CoverConfig{Mode: CoverOff, CellSizeBytes: 1024, IntervalMs: 20, MaxOverhead: 0.5},
		Payments:    PaymentsConfig{MaxPerHourDero: 1.0, Confirmations: 1, Currency: "DERO"},
		Logging:     LoggingConfig{Level: "info"},
	}
}

// ClientConfigPath returns ~/.veilnet/config.toml.
func ClientConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".veilnet", "config.toml"), nil
}

// NodeConfigPath returns ~/.veilnet-node/config.toml.
func NodeConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".veilnet-node", "config.toml"), nil
}

// LoadClient loads path, or the default client path when path == "".
// Missing file yields defaults (no error).
func LoadClient(path string) (ClientConfig, error) {
	cfg := DefaultClientConfig()
	if path == "" {
		p, err := ClientConfigPath()
		if err != nil {
			return cfg, err
		}
		path = p
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// Save writes cfg to path (default client path when empty) with 0600
// permissions and a 0700 parent dir. Secrets stay in the file only.
func (c ClientConfig) Save(path string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if path == "" {
		p, err := ClientConfigPath()
		if err != nil {
			return err
		}
		path = p
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	encErr := toml.NewEncoder(f).Encode(c)
	closeErr := f.Close()
	// Best-effort owner-only lockdown for secrets. Enforced on
	// Unix; on Windows Go can only set the read-only bit, so the
	// token/config rely on the user profile ACL instead.
	_ = os.Chmod(path, 0o600)
	if encErr != nil {
		return encErr
	}
	return closeErr
}

// Validate rejects unknown enum values.
func (c ClientConfig) Validate() error {
	switch c.KillSwitch {
	case KillOff, KillWhileConnected, KillAlwaysOn:
	default:
		return fmt.Errorf("invalid killswitch mode %q", c.KillSwitch)
	}
	switch c.DNS.Mode {
	case DNSVeilnet, DNSCustom, DNSDoH, DNSModeSystem:
	default:
		return fmt.Errorf("invalid dns mode %q", c.DNS.Mode)
	}
	switch c.Network.SelectPolicy {
	case "", SelectFastest, SelectLowestLoad, SelectLowestPrice, SelectPrivacy, SelectSpecificReg:
	default:
		return fmt.Errorf("invalid select policy %q", c.Network.SelectPolicy)
	}
	switch c.Wallet.Mode {
	case "", WalletModeNone, WalletModeRPC, WalletModeXSWD:
	default:
		return fmt.Errorf("invalid wallet mode %q", c.Wallet.Mode)
	}
	switch c.Cover.Mode {
	case "", CoverOff:
	case CoverPad:
	case CoverConstant:
		if c.Cover.CellSizeBytes <= 0 {
			return fmt.Errorf("cover mode CONSTANT needs cell_size_bytes > 0")
		}
		if c.Cover.IntervalMs <= 0 {
			return fmt.Errorf("cover mode CONSTANT needs interval_ms > 0")
		}
	default:
		return fmt.Errorf("invalid cover mode %q", c.Cover.Mode)
	}
	if c.Cover.MaxOverhead < 0 {
		return fmt.Errorf("cover max_overhead must be >= 0")
	}
	return nil
}

// Redacted returns a copy with secret fields masked. Log this, never c.
func (c ClientConfig) Redacted() ClientConfig {
	out := c
	out.Dero.RPCPassword = maskSecret(out.Dero.RPCPassword)
	out.Wallet.Password = maskSecret(out.Wallet.Password)
	return out
}

func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	return "***"
}
