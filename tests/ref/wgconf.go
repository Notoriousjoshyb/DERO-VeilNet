package ref

import (
	"errors"
	"fmt"
	"strings"
)

// RenderWgConf renders a WireGuardConfig to INI text for wg-quick style
// consumers. It validates the same invariants as the engine: key, addresses,
// peers with keys/endpoints/AllowedIPs. Keepalive <= 0 omits the line.
func RenderWgConf(cfg WireGuardConfig) (string, error) {
	if err := validateConfig(cfg); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", cfg.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", strings.Join(cfg.Addresses, ", "))
	if len(cfg.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(cfg.DNS, ", "))
	}
	for _, p := range cfg.Peers {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.Keepalive)
		}
	}
	return b.String(), nil
}

// ParseWgConfEndpoints extracts peer endpoints from rendered INI. Used to
// assert render/rotate round-trips without parsing WireGuard binaries.
func ParseWgConfEndpoints(ini string) ([]string, error) {
	var out []string
	for _, line := range strings.Split(ini, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Endpoint = ") {
			ep := strings.TrimPrefix(line, "Endpoint = ")
			if ep == "" {
				return nil, errors.New("ref: empty endpoint in conf")
			}
			out = append(out, ep)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("ref: no peers in conf")
	}
	return out, nil
}
