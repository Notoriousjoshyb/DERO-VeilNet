package dns

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dero-veilnet/veilnet/internal/platform"
)

func init() {
	platform.Register(platform.KindDNS, linuxBackend{}.Name(), linuxBackend{}.Supports)
}

// resolvConfDefault is the fallback resolver file used when
// systemd-resolved is absent.
const resolvConfDefault = "/etc/resolv.conf"

// linuxBackend manages DNS via systemd-resolved (`resolvectl`) with an
// /etc/resolv.conf fallback. The fallback keeps a backup in the snapshot
// flow: prior resolvers are restored byte-for-byte from the manager's
// snapshot, and the leak state always reflects the effective file.
type linuxBackend struct {
	// ResolvConfPath overrides the fallback resolver file (tests).
	ResolvConfPath string
}

func (b linuxBackend) Name() string   { return "systemd-resolved" }
func (b linuxBackend) Supports() bool { return platform.CurrentOS() == platform.Linux }

func (b linuxBackend) resolvConf() string {
	if b.ResolvConfPath != "" {
		return b.ResolvConfPath
	}
	return resolvConfDefault
}

func (b linuxBackend) hasResolved(run Runner) bool {
	_, err := run.Run("resolvectl", "--version")
	return err == nil
}

func (b linuxBackend) Current(run Runner, iface string) []string {
	if b.hasResolved(run) {
		out, err := run.Run("resolvectl", "dns", iface)
		if err != nil {
			return nil
		}
		return parseIPs(out)
	}
	raw, err := os.ReadFile(b.resolvConf())
	if err != nil {
		return nil
	}
	return parseResolvConf(raw)
}

func (b linuxBackend) Set(run Runner, iface string, servers []string) error {
	if b.hasResolved(run) {
		args := append([]string{"dns", iface}, servers...)
		if _, err := run.Run("resolvectl", args...); err != nil {
			return fmt.Errorf("dns: resolvectl dns: %w", err)
		}
		if _, err := run.Run("resolvectl", "domain", iface, "~."); err != nil {
			return fmt.Errorf("dns: resolvectl domain: %w", err)
		}
		return nil
	}
	return b.writeResolvConf(servers)
}

func (b linuxBackend) RegisterDOH(run Runner, servers []string) error {
	for _, s := range servers {
		if _, ok := dohTemplates[s]; !ok {
			return fmt.Errorf("dns: no known DoH template for %s (refusing silent downgrade)", s)
		}
	}
	return fmt.Errorf("dns: DoH registration needs Windows 11 (netsh dns encryption); %d server(s) not registered on linux (use VEILNET/CUSTOM)", len(servers))
}

func (b linuxBackend) Restore(run Runner, iface string, prior []string) error {
	if b.hasResolved(run) {
		if _, err := run.Run("resolvectl", "revert", iface); err != nil {
			return fmt.Errorf("dns: resolvectl revert: %w", err)
		}
		// The fallback file is only authoritative when resolved is
		// absent; still, restore it when we manage it so no tunnel
		// nameserver lingers anywhere.
		if _, serr := os.Stat(b.resolvConf()); serr == nil {
			raw, rerr := os.ReadFile(b.resolvConf())
			if rerr == nil && resolvConfManaged(raw) {
				return b.writeResolvConf(prior)
			}
		}
		return nil
	}
	return b.writeResolvConf(prior)
}

func (b linuxBackend) Effective(run Runner, iface string) []string {
	if b.hasResolved(run) {
		out, err := run.Run("resolvectl", "dns", iface)
		if err == nil {
			if got := parseIPs(out); len(got) > 0 {
				return got
			}
		}
	}
	raw, err := os.ReadFile(b.resolvConf())
	if err != nil {
		return nil
	}
	return parseResolvConf(raw)
}

// resolvHeader marks files written by the fallback path.
const resolvHeader = "# VeilNet managed (fallback: systemd-resolved absent)\n"

func resolvConfManaged(raw []byte) bool {
	return strings.Contains(string(raw), "VeilNet managed")
}

func (b linuxBackend) writeResolvConf(servers []string) error {
	var sb strings.Builder
	sb.WriteString(resolvHeader)
	for _, s := range servers {
		fmt.Fprintf(&sb, "nameserver %s\n", s)
	}
	p := b.resolvConf()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("dns: resolv.conf dir: %w", err)
	}
	if err := os.WriteFile(p, []byte(sb.String()), 0o644); err != nil {
		return fmt.Errorf("dns: write resolv.conf: %w", err)
	}
	return nil
}

func parseResolvConf(raw []byte) []string {
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) == 2 && f[0] == "nameserver" && isIP(f[1]) {
			out = append(out, f[1])
		}
	}
	return out
}

func parseIPs(out string) []string {
	var servers []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(out, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ' ' || r == ',' || r == ':' || r == '(' || r == ')'
	}) {
		if isIP(f) && !seen[f] {
			seen[f] = true
			servers = append(servers, f)
		}
	}
	return servers
}
