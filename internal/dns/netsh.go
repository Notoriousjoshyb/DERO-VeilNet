package dns

import (
	"fmt"
	"strings"

	"github.com/dero-veilnet/veilnet/internal/platform"
)

func init() {
	platform.Register(platform.KindDNS, windowsBackend{}.Name(), windowsBackend{}.Supports)
}

// windowsBackend manages DNS via netsh interface DNS + a
// Name Resolution Policy Table (NRPT) catch-all.
type windowsBackend struct{}

func (b windowsBackend) Name() string     { return "netsh-nrpt" }
func (b windowsBackend) Supports() bool   { return platform.CurrentOS() == platform.Windows }

// nrptRuleBase names NRPT rules so only ours are ever removed.
const nrptRuleBase = "VeilNet"

// nrptCatchAll is the deterministic catch-all rule name.
const nrptCatchAll = nrptRuleBase + "-CatchAll"

// dohTemplates maps well-known resolver IPs to their HTTPS templates.
// Servers outside this map are rejected rather than silently downgraded.
var dohTemplates = map[string]string{
	"1.1.1.1": "https://cloudflare-dns.com/dns-query",
	"1.0.0.1": "https://cloudflare-dns.com/dns-query",
	"8.8.8.8": "https://dns.google/dns-query",
	"8.8.4.4": "https://dns.google/dns-query",
	"9.9.9.9": "https://dns.quad9.net/dns-query",
}

func (b windowsBackend) Current(run Runner, iface string) []string {
	out, err := run.Run("netsh", "interface", "ip", "show", "dns",
		fmt.Sprintf(`name="%s"`, iface))
	if err != nil {
		return nil
	}
	var servers []string
	for _, line := range strings.Split(out, "\n") {
		for _, f := range strings.Fields(line) {
			f = strings.Trim(f, ",")
			if isIP(f) {
				servers = append(servers, f)
			}
		}
	}
	return servers
}

func (b windowsBackend) Set(run Runner, iface string, servers []string) error {
	primary := servers[0]
	if _, err := run.Run("netsh", "interface", "ip", "set", "dns",
		fmt.Sprintf(`name="%s"`, iface), "static", primary); err != nil {
		return fmt.Errorf("dns: set primary: %w", err)
	}
	for _, extra := range servers[1:] {
		if _, err := run.Run("netsh", "interface", "ip", "add", "dns",
			fmt.Sprintf(`name="%s"`, iface), extra, "index=2"); err != nil {
			return fmt.Errorf("dns: add resolver: %w", err)
		}
	}
	return b.addNRPT(run, servers)
}

func (b windowsBackend) RegisterDOH(run Runner, servers []string) error {
	for _, s := range servers {
		tpl, ok := dohTemplates[s]
		if !ok {
			return fmt.Errorf("dns: no known DoH template for %s (refusing silent downgrade)", s)
		}
		if _, err := run.Run("netsh", "dns", "add", "encryption",
			"server="+s, "dohtemplate="+tpl, "autoupgrade=yes"); err != nil {
			return fmt.Errorf("dns: register DoH for %s: %w", s, err)
		}
	}
	return nil
}

func (b windowsBackend) Restore(run Runner, iface string, prior []string) error {
	b.removeNRPT(run, []string{nrptCatchAll})
	var first error
	if _, err := run.Run("netsh", "interface", "ip", "set", "dns",
		fmt.Sprintf(`name="%s"`, iface), "dhcp"); err != nil {
		first = err
	}
	for _, srv := range prior {
		// Re-add original static servers if the snapshot had any.
		if _, err := run.Run("netsh", "interface", "ip", "add", "dns",
			fmt.Sprintf(`name="%s"`, iface), srv); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (b windowsBackend) Effective(run Runner, iface string) []string {
	out, err := run.Run("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses`)
	if err != nil {
		return b.Current(run, iface)
	}
	var out2 []string
	seen := map[string]bool{}
	for _, f := range strings.FieldsFunc(out, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ' ' || r == ','
	}) {
		if isIP(f) && !seen[f] {
			seen[f] = true
			out2 = append(out2, f)
		}
	}
	return out2
}

func (b windowsBackend) addNRPT(run Runner, servers []string) error {
	ns := strings.Join(servers, ",")
	script := fmt.Sprintf(
		`Get-DnsClientNrptRule -Name "%s" -ErrorAction SilentlyContinue | Remove-DnsClientNrptRule -Force; `+
			`Add-DnsClientNrptRule -Namespace "." -NameServers "%s" -Name "%s" -Comment "VeilNet managed"`,
		nrptCatchAll, ns, nrptCatchAll)
	if _, err := run.Run("powershell", "-NoProfile", "-NonInteractive", "-Command", script); err != nil {
		return fmt.Errorf("dns: NRPT: %w", err)
	}
	return nil
}

func (b windowsBackend) removeNRPT(run Runner, names []string) {
	for _, n := range names {
		script := fmt.Sprintf(
			`Get-DnsClientNrptRule -Name "%s" -ErrorAction SilentlyContinue | Remove-DnsClientNrptRule -Force`, n)
		_, _ = run.Run("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	}
}
