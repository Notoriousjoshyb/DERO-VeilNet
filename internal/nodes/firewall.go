package nodes

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// Commands returns the forwarding+NAT commands for the current OS in
// dry-run form. ApplyFirewall executes the Linux subset best-effort;
// a missing tool never fails the daemon (warn in logs instead).
func (c *Config) firewallCommands() []string {
	iface := c.WGInterface
	var cmds []string
	switch runtime.GOOS {
	case "windows":
		// netsh + PowerShell routing; exact NIC names vary — see operator doc.
		cmds = append(cmds,
			fmt.Sprintf(`netsh interface portproxy reset`),
			fmt.Sprintf(`netsh advfirewall firewall add rule name="veilnet-%s-in" dir=in action=allow protocol=UDP localport=%d`, iface, c.WGListenPort),
			fmt.Sprintf(`# Enable IP forwarding: Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters IPEnableRouter 1`),
			fmt.Sprintf(`# NAT via Internet Connection Sharing or New-NetNat -Name veilnet -InternalIPInterfaceAddressPrefix %s`, c.CGNAT),
		)
	case "darwin":
		cmds = append(cmds,
			fmt.Sprintf(`# sysctl -w net.inet.ip.forwarding=1`),
			fmt.Sprintf(`# echo "nat on en0 from %s to any -> (en0)" | sudo pfctl -ef -`, c.CGNAT),
		)
	default: // linux: iptables preferred, nft fallback documented.
		cmds = append(cmds,
			`sysctl -w net.ipv4.ip_forward=1`,
			fmt.Sprintf(`iptables -C FORWARD -i %s -j ACCEPT 2>/dev/null || iptables -A FORWARD -i %s -j ACCEPT`, iface, iface),
			fmt.Sprintf(`iptables -C FORWARD -o %s -j ACCEPT 2>/dev/null || iptables -A FORWARD -o %s -j ACCEPT`, iface, iface),
			fmt.Sprintf(`iptables -t nat -C POSTROUTING -s %s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s %s -j MASQUERADE`, c.CGNAT, c.CGNAT),
		)
		// Egress port policy.
		for _, p := range c.DeniedPorts {
			cmds = append(cmds, fmt.Sprintf(`iptables -A FORWARD -i %s -p tcp --dport %d -j REJECT  # operator deny`, iface, p))
		}
		if !c.DefaultAllow {
			cmds = append(cmds, fmt.Sprintf(`iptables -A FORWARD -i %s -j REJECT  # default-deny egress`, iface))
			for _, p := range c.AllowedPorts {
				cmds = append(cmds, fmt.Sprintf(`iptables -I FORWARD -i %s -p tcp --dport %d -j ACCEPT  # operator allow`, iface, p))
			}
		}
	}
	return cmds
}

// FirewallCommands exposes the dry-run command list for docs/diagnostics.
func (c *Config) FirewallCommands() []string { return c.firewallCommands() }

// ApplyFirewall enables forwarding + NAT best-effort. Only the
// sysctl + iptables path is executed, and only on Linux; every other
// platform returns the command list as an error-free dry run so the
// operator can apply it manually. Never fatal.
func ApplyFirewall(c *Config) ([]string, error) {
	cmds := c.firewallCommands()
	if runtime.GOOS != "linux" {
		return cmds, nil
	}
	var warnings []string
	run := func(name string, args ...string) {
		cmd := exec.Command(name, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s %s: %v (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out))))
		}
	}
	run("sysctl", "-w", "net.ipv4.ip_forward=1")
	if _, err := exec.LookPath("iptables"); err != nil {
		warnings = append(warnings, "iptables not found; skipping NAT setup (see docs/NODE_OPERATOR.md)")
		return cmds, firewallWarning(warnings)
	}
	iptables := func(args ...string) {
		// Idempotent add: try -C first, fall back to -A.
		check := append([]string{"-C"}, args...)
		if err := exec.Command("iptables", check...).Run(); err == nil {
			return
		}
		add := append([]string{"-A"}, args...)
		run("iptables", add...)
	}
	iptables("FORWARD", "-i", c.WGInterface, "-j", "ACCEPT")
	iptables("FORWARD", "-o", c.WGInterface, "-j", "ACCEPT")
	// NAT rule needs the -t nat table; handle separately.
	if err := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", c.CGNAT, "-j", "MASQUERADE").Run(); err != nil {
		run("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", c.CGNAT, "-j", "MASQUERADE")
	}
	return cmds, firewallWarning(warnings)
}

func firewallWarning(warnings []string) error {
	if len(warnings) == 0 {
		return nil
	}
	return &FirewallWarning{Details: warnings}
}

// FirewallWarning is a non-fatal aggregate of firewall setup warnings.
type FirewallWarning struct{ Details []string }

// Error implements error.
func (w *FirewallWarning) Error() string {
	return "nodes: firewall warnings: " + strings.Join(w.Details, "; ")
}
