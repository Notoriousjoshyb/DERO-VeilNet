// Package wireguard implements WireGuard configuration handling for VeilNet:
// key generation (via library curve25519, never custom crypto), INI
// (wg-quick style) generation/parsing, and IPC formatting for configuring
// wireguard-go userspace devices.
//
// Addresses/DNS never enter the device IPC blob: they are applied to the TUN
// interface and routing/DNS layers by the caller.
package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Key length in bytes for WireGuard Curve25519 keys.
const KeyLen = 32

// Peer is one WireGuard peer entry.
type Peer struct {
	// PublicKey is the base64 WireGuard public key of the peer.
	PublicKey string
	// Endpoint is host:port of the peer (may be empty for roaming peers).
	Endpoint string
	// AllowedIPs is the list of CIDRs routed to this peer.
	AllowedIPs []string
	// Keepalive is the persistent-keepalive interval in seconds; 0 disables it.
	Keepalive int
}

// Config is a full WireGuard interface configuration.
type Config struct {
	// PrivateKey is the base64 WireGuard private key of the local interface.
	PrivateKey string
	// ListenPort is the local UDP port; 0 leaves device default/ephemeral.
	ListenPort int
	// Addresses are CIDRs assigned to the TUN interface (not passed to device).
	Addresses []string
	// DNS are resolver IPs pushed to the DNS layer (not passed to device).
	DNS []string
	// Peers is the peer list.
	Peers []Peer
	// MTU applied to the TUN interface; 0 uses 1420.
	MTU int
}

// MTUOrDefault returns the configured MTU or the WireGuard default.
func (c Config) MTUOrDefault() int {
	if c.MTU > 0 {
		return c.MTU
	}
	return 1420
}

// GenerateKeypair creates a fresh random WireGuard keypair.
//
// Randomness comes from crypto/rand; the public key is derived with the
// curve25519 scalar-mult from golang.org/x/crypto. No custom crypto.
func GenerateKeypair() (priv, pub string, err error) {
	var sk [KeyLen]byte
	if _, err := rand.Read(sk[:]); err != nil {
		return "", "", fmt.Errorf("wireguard: entropy: %w", err)
	}
	// Clamp exactly as WireGuard requires.
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64
	pk, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("wireguard: derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sk[:]),
		base64.StdEncoding.EncodeToString(pk), nil
}

// PublicKeyFor derives the base64 public key for a base64 private key.
func PublicKeyFor(priv string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(raw) != KeyLen {
		return "", fmt.Errorf("wireguard: bad private key")
	}
	var sk [KeyLen]byte
	copy(sk[:], raw)
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64
	pk, err := curve25519.X25519(sk[:], curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("wireguard: derive public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pk), nil
}

// privateKeyHex decodes a base64 private key to lowercase hex (IPC format).
func privateKeyHex(priv string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(priv))
	if err != nil || len(raw) != KeyLen {
		return "", fmt.Errorf("wireguard: bad private key")
	}
	return hex.EncodeToString(raw), nil
}

// publicKeyHex decodes a base64 public key to lowercase hex (IPC format).
func publicKeyHex(pub string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pub))
	if err != nil || len(raw) != KeyLen {
		return "", fmt.Errorf("wireguard: bad public key %q", pub)
	}
	return hex.EncodeToString(raw), nil
}

// Validate checks keys, addresses, endpoints and CIDRs without touching the OS.
func Validate(cfg Config) error {
	if _, err := privateKeyHex(cfg.PrivateKey); err != nil {
		return err
	}
	if cfg.ListenPort < 0 || cfg.ListenPort > 65535 {
		return fmt.Errorf("wireguard: bad listen port %d", cfg.ListenPort)
	}
	for _, a := range cfg.Addresses {
		if _, err := netip.ParsePrefix(a); err != nil {
			return fmt.Errorf("wireguard: bad address %q: %w", a, err)
		}
	}
	for _, d := range cfg.DNS {
		if net.ParseIP(d) == nil {
			return fmt.Errorf("wireguard: bad DNS ip %q", d)
		}
	}
	if len(cfg.Peers) == 0 {
		return fmt.Errorf("wireguard: at least one peer is required")
	}
	for i := range cfg.Peers {
		if _, err := publicKeyHex(cfg.Peers[i].PublicKey); err != nil {
			return fmt.Errorf("wireguard: peer %d: %w", i, err)
		}
		if ep := strings.TrimSpace(cfg.Peers[i].Endpoint); ep != "" {
			h, p, err := net.SplitHostPort(ep)
			if err != nil || h == "" {
				return fmt.Errorf("wireguard: peer %d: bad endpoint %q", i, cfg.Peers[i].Endpoint)
			}
			n, err := strconv.Atoi(p)
			if err != nil || n <= 0 || n > 65535 {
				return fmt.Errorf("wireguard: peer %d: bad endpoint port %q", i, cfg.Peers[i].Endpoint)
			}
		}
		for _, a := range cfg.Peers[i].AllowedIPs {
			if _, err := netip.ParsePrefix(a); err != nil {
				return fmt.Errorf("wireguard: peer %d: bad allowed_ip %q", i, a)
			}
		}
		if cfg.Peers[i].Keepalive < 0 {
			return fmt.Errorf("wireguard: peer %d: negative keepalive", i)
		}
	}
	return nil
}

// GenerateINI renders cfg in wg-quick INI format.
func GenerateINI(cfg Config) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + strings.TrimSpace(cfg.PrivateKey) + "\n")
	if len(cfg.Addresses) > 0 {
		b.WriteString("Address = " + strings.Join(cfg.Addresses, ", ") + "\n")
	}
	if len(cfg.DNS) > 0 {
		b.WriteString("DNS = " + strings.Join(cfg.DNS, ", ") + "\n")
	}
	if cfg.ListenPort > 0 {
		b.WriteString(fmt.Sprintf("ListenPort = %d\n", cfg.ListenPort))
	}
	if cfg.MTU > 0 {
		b.WriteString(fmt.Sprintf("MTU = %d\n", cfg.MTU))
	}
	for _, p := range cfg.Peers {
		b.WriteString("\n[Peer]\n")
		b.WriteString("PublicKey = " + strings.TrimSpace(p.PublicKey) + "\n")
		if strings.TrimSpace(p.Endpoint) != "" {
			b.WriteString("Endpoint = " + strings.TrimSpace(p.Endpoint) + "\n")
		}
		if len(p.AllowedIPs) > 0 {
			b.WriteString("AllowedIPs = " + strings.Join(p.AllowedIPs, ", ") + "\n")
		}
		if p.Keepalive > 0 {
			b.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", p.Keepalive))
		}
	}
	return b.String()
}

// ParseINI parses wg-quick style INI back into a Config.
// Unknown keys are ignored so node-provided files stay forward compatible.
func ParseINI(s string) (Config, error) {
	var cfg Config
	var cur *Peer
	splitList := func(v string) []string {
		var out []string
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f != "" {
				out = append(out, f)
			}
		}
		return out
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			switch strings.ToLower(strings.TrimSpace(line[1 : len(line)-1])) {
			case "interface":
				cur = nil
			case "peer":
				cfg.Peers = append(cfg.Peers, Peer{})
				cur = &cfg.Peers[len(cfg.Peers)-1]
			default:
				cur = nil
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if cur == nil {
			switch k {
			case "privatekey":
				cfg.PrivateKey = v
			case "address":
				cfg.Addresses = append(cfg.Addresses, splitList(v)...)
			case "dns":
				cfg.DNS = append(cfg.DNS, splitList(v)...)
			case "listenport":
				n, err := strconv.Atoi(v)
				if err != nil {
					return Config{}, fmt.Errorf("wireguard: bad ListenPort %q", v)
				}
				cfg.ListenPort = n
			case "mtu":
				n, err := strconv.Atoi(v)
				if err != nil {
					return Config{}, fmt.Errorf("wireguard: bad MTU %q", v)
				}
				cfg.MTU = n
			}
			continue
		}
		switch k {
		case "publickey":
			cur.PublicKey = v
		case "endpoint":
			cur.Endpoint = v
		case "allowedips":
			cur.AllowedIPs = append(cur.AllowedIPs, splitList(v)...)
		case "persistentkeepalive":
			n, err := strconv.Atoi(v)
			if err != nil {
				return Config{}, fmt.Errorf("wireguard: bad PersistentKeepalive %q", v)
			}
			cur.Keepalive = n
		}
	}
	if strings.TrimSpace(cfg.PrivateKey) == "" {
		return Config{}, fmt.Errorf("wireguard: missing Interface PrivateKey")
	}
	return cfg, nil
}

// ToIPC renders cfg in the WireGuard IPC format consumed by
// wireguard-go device.IpcSet and the cross-platform `wg setconf` pipe.
// Addresses and DNS are intentionally excluded: they belong to the TUN
// interface and DNS layer, not the device.
func ToIPC(cfg Config) (string, error) {
	if err := Validate(cfg); err != nil {
		return "", err
	}
	sk, err := privateKeyHex(cfg.PrivateKey)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("private_key=" + sk + "\n")
	if cfg.ListenPort > 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", cfg.ListenPort)
	}
	for _, p := range cfg.Peers {
		pk, err := publicKeyHex(p.PublicKey)
		if err != nil {
			return "", err
		}
		b.WriteString("public_key=" + pk + "\n")
		if strings.TrimSpace(p.Endpoint) != "" {
			b.WriteString("endpoint=" + strings.TrimSpace(p.Endpoint) + "\n")
		}
		ips := append([]string(nil), p.AllowedIPs...)
		sort.Strings(ips)
		for _, a := range ips {
			b.WriteString("allowed_ip=" + strings.TrimSpace(a) + "\n")
		}
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.Keepalive)
		}
	}
	return b.String(), nil
}

// PeerStats is per-peer traffic data scraped from a device IPC dump.
type PeerStats struct {
	PublicKeyHex  string
	RxBytes       uint64
	TxBytes       uint64
	LastHandshake time.Time
	Endpoint      string
	AllowedIPs    []string
	KeepaliveSecs int
}

// ParseIPCDump parses the output of device.IpcGet (or `wg show all dump`
// style IPC text) into per-peer stats. Unknown lines are ignored.
func ParseIPCDump(dump string) []PeerStats {
	var out []PeerStats
	var cur *PeerStats
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}
	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "public_key":
			flush()
			cur = &PeerStats{PublicKeyHex: strings.TrimSpace(v)}
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes = parseUint(v)
			}
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes = parseUint(v)
			}
		case "last_handshake_time_sec":
			if cur != nil {
				if sec, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil && sec > 0 {
					cur.LastHandshake = time.Unix(sec, 0)
				}
			}
		case "endpoint":
			if cur != nil {
				cur.Endpoint = strings.TrimSpace(v)
			}
		case "allowed_ip":
			if cur != nil {
				cur.AllowedIPs = append(cur.AllowedIPs, strings.TrimSpace(v))
			}
		case "persistent_keepalive_interval":
			if cur != nil {
				if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
					cur.KeepaliveSecs = n
				}
			}
		}
	}
	flush()
	return out
}

// AggregateStats sums rx/tx across peers and returns the newest handshake.
func AggregateStats(peers []PeerStats) (rx, tx uint64, last time.Time) {
	for _, p := range peers {
		rx += p.RxBytes
		tx += p.TxBytes
		if p.LastHandshake.After(last) {
			last = p.LastHandshake
		}
	}
	return rx, tx, last
}

func parseUint(s string) uint64 {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}
