package firewall

import (
	"fmt"
	"strings"

	"github.com/dero-veilnet/veilnet/internal/platform"
)

func init() {
	platform.Register(platform.KindFirewall, windowsBackend{}.Name(), windowsBackend{}.Supports)
}

// windowsBackend enforces the kill switch via `netsh advfirewall firewall`.
type windowsBackend struct{}

func (b windowsBackend) Name() string { return "netsh" }
func (b windowsBackend) Supports() bool { return platform.CurrentOS() == platform.Windows }

// ruleGroup groups every rule this backend owns (cleanup + audit).
const ruleGroup = "VeilNet Kill Switch"

func (b windowsBackend) RuleNames(spec Spec) []string {
	return ruleNames(allowRules(spec.EndpointIP, spec.EndpointPort, spec.TunAddr, spec.LANAllowed))
}

func (b windowsBackend) Enable(run Runner, spec Spec) error {
	for _, args := range allowRules(spec.EndpointIP, spec.EndpointPort, spec.TunAddr, spec.LANAllowed) {
		full := append([]string{"advfirewall", "firewall", "add", "rule"}, args...)
		if _, err := run.Run("netsh", full...); err != nil {
			return fmt.Errorf("firewall: add rule: %w", err)
		}
	}
	return nil
}

func (b windowsBackend) Remove(run Runner, names []string) error {
	var first error
	for _, n := range names {
		if _, err := run.Run("netsh", "advfirewall", "firewall", "delete", "rule", "name="+n); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (b windowsBackend) SetBlock(run Runner) error {
	_, err := run.Run("netsh", "advfirewall", "set", "allprofiles",
		"firewallpolicy", "blockinbound,blockoutbound")
	return err
}

func (b windowsBackend) Restore(run Runner, policy string) error {
	_, err := run.Run("netsh", "advfirewall", "set", "allprofiles",
		"firewallpolicy", policy)
	return err
}

func (b windowsBackend) CurrentPolicy(run Runner) (string, error) {
	out, err := run.Run("netsh", "advfirewall", "show", "allprofiles")
	if err != nil {
		return "", err
	}
	// Parse the outbound policy; fall back to the Windows default when the
	// locale/format is unexpected (restore then returns to default).
	// The value looks like "BlockInbound,AllowOutbound". Only the outbound
	// half decides; matching "blockoutbound" exactly keeps "BlockInbound"
	// from ever reading as a blocked outbound default.
	policy := "blockinbound,allowoutbound"
	for _, line := range strings.Split(out, "\n") {
		l := strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(l, "firewall policy") && strings.Contains(l, "blockoutbound") {
			policy = "blockinbound,blockoutbound"
		}
	}
	return policy, nil
}

// allowRules builds ordered netsh rule fragments (without the leading
// "advfirewall firewall add rule").
func allowRules(endpointIP string, endpointPort int, tunAddr string, lan bool) [][]string {
	base := []string{"group=" + quoted(ruleGroup), "enable=yes"}
	rules := [][]string{
		append(base, "name=VeilNet-KS-Allow-Endpoint", "dir=out", "action=allow",
			"protocol=UDP", "remoteip="+endpointIP, fmt.Sprintf("remoteport=%d", endpointPort)),
		append(base, "name=VeilNet-KS-Allow-Tunnel-Out", "dir=out", "action=allow",
			"localip="+tunAddr),
		append(base, "name=VeilNet-KS-Allow-Tunnel-In", "dir=in", "action=allow",
			"remoteip="+tunAddr),
		// DHCP must bypass the tunnel (broadcast, pre-lease).
		append(base, "name=VeilNet-KS-Allow-DHCP-Out", "dir=out", "action=allow",
			"protocol=UDP", "remoteip=255.255.255.255", "remoteport=67"),
		append(base, "name=VeilNet-KS-Allow-DHCP-In", "dir=in", "action=allow",
			"protocol=UDP", "localport=68"),
	}
	if lan {
		rules = append(rules, append(base, "name=VeilNet-KS-Allow-LAN", "dir=out", "action=allow",
			"remoteip=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"))
	}
	return rules
}

func ruleNames(rules [][]string) []string {
	var out []string
	for _, r := range rules {
		for _, tok := range r {
			if v, ok := strings.CutPrefix(tok, "name="); ok {
				out = append(out, v)
			}
		}
	}
	return out
}

func quoted(s string) string { return `"` + s + `"` }
