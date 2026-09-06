package dns

import (
	"fmt"
	"strings"

	"github.com/dero-veilnet/veilnet/internal/platform"
)

func init() {
	platform.Register(platform.KindDNS, darwinBackend{}.Name(), darwinBackend{}.Supports)
}

// darwinBackend manages DNS via networksetup with an scutil fallback for
// leak queries. Prior resolvers persist in the manager snapshot so
// Restore reinstates them exactly (never brick).
type darwinBackend struct{}

func (b darwinBackend) Name() string   { return "networksetup" }
func (b darwinBackend) Supports() bool { return platform.CurrentOS() == platform.Darwin }

func (b darwinBackend) Current(run Runner, iface string) []string {
	out, err := run.Run("networksetup", "-getdnsservers", iface)
	if err != nil {
		return nil
	}
	if strings.Contains(out, "There aren't any") {
		return nil
	}
	return parseIPs(out)
}

func (b darwinBackend) Set(run Runner, iface string, servers []string) error {
	args := append([]string{"-setdnsservers", iface}, servers...)
	if _, err := run.Run("networksetup", args...); err != nil {
		return fmt.Errorf("dns: networksetup set: %w (service name must match the tunnel service; see docs/PLATFORM.md)", err)
	}
	return nil
}

func (b darwinBackend) RegisterDOH(run Runner, servers []string) error {
	for _, s := range servers {
		if _, ok := dohTemplates[s]; !ok {
			return fmt.Errorf("dns: no known DoH template for %s (refusing silent downgrade)", s)
		}
	}
	return fmt.Errorf("dns: DoH registration needs Windows 11 (netsh dns encryption); %d server(s) not registered on darwin (use VEILNET/CUSTOM)", len(servers))
}

func (b darwinBackend) Restore(run Runner, iface string, prior []string) error {
	args := []string{"-setdnsservers", iface}
	if len(prior) == 0 {
		args = append(args, "Empty")
	} else {
		args = append(args, prior...)
	}
	if _, err := run.Run("networksetup", args...); err != nil {
		return fmt.Errorf("dns: networksetup restore: %w", err)
	}
	return nil
}

func (b darwinBackend) Effective(run Runner, iface string) []string {
	if out, err := run.Run("networksetup", "-getdnsservers", iface); err == nil {
		if !strings.Contains(out, "There aren't any") {
			if got := parseIPs(out); len(got) > 0 {
				return got
			}
		}
	}
	out, err := run.Run("scutil", "--dns")
	if err != nil {
		return nil
	}
	var servers []string
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "nameserver["); ok {
			if i := strings.Index(v, ":"); i >= 0 {
				ip := strings.TrimSpace(v[i+1:])
				if isIP(ip) && !seen[ip] {
					seen[ip] = true
					servers = append(servers, ip)
				}
			}
		}
	}
	return servers
}
