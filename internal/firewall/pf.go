package firewall

import (
	"fmt"
	"os"
	"strings"

	"github.com/dero-veilnet/veilnet/internal/platform"
)

func init() {
	platform.Register(platform.KindFirewall, darwinBackend{}.Name(), darwinBackend{}.Supports)
}

// pfAnchor is the single pf anchor this backend owns. Disable flushes the
// whole anchor, so no rule can ever linger (zero residual by construction).
const pfAnchor = "com.veilnet.killswitch"

// darwinBackend enforces the kill switch with a pf anchor. Fail-closed
// semantics mirror the netsh backend: handshake UDP + tunnel-local +
// DHCP/DNS-to-tunnel + optional LAN pass, everything else is blocked;
// on unexpected tunnel loss the anchor STAYS until an explicit Disable.
type darwinBackend struct{}

func (b darwinBackend) Name() string { return "pf" }
func (b darwinBackend) Supports() bool { return platform.CurrentOS() == platform.Darwin }

func (b darwinBackend) RuleNames(spec Spec) []string {
	names := []string{pfAnchor + ":endpoint", pfAnchor + ":tunnel", pfAnchor + ":dhcp"}
	if spec.LANAllowed {
		names = append(names, pfAnchor+":lan")
	}
	return names
}

// AnchorRules renders the pf rules loaded into the anchor for spec.
// It is a pure function so tests can assert exact allow-list semantics.
func (_ darwinBackend) AnchorRules(spec Spec) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# %s (VeilNet kill switch: fail-closed allow-list)\n", pfAnchor)
	fmt.Fprintf(&sb, "pass out proto udp to %s port %d # veilnet-ks-endpoint\n", spec.EndpointIP, spec.EndpointPort)
	fmt.Fprintf(&sb, "pass out inet from %s to any # veilnet-ks-tunnel\n", spec.TunAddr)
	fmt.Fprintf(&sb, "pass in inet from %s to any # veilnet-ks-tunnel\n", spec.TunAddr)
	fmt.Fprintf(&sb, "pass out proto udp to 255.255.255.255 port 67 # veilnet-ks-dhcp\n")
	fmt.Fprintf(&sb, "pass in proto udp from any port 67 to any port 68 # veilnet-ks-dhcp\n")
	if spec.LANAllowed {
		fmt.Fprintf(&sb, "pass out inet to 10.0.0.0/8 # veilnet-ks-lan\n")
		fmt.Fprintf(&sb, "pass out inet to 172.16.0.0/12 # veilnet-ks-lan\n")
		fmt.Fprintf(&sb, "pass out inet to 192.168.0.0/16 # veilnet-ks-lan\n")
	}
	sb.WriteString("block out all # veilnet-ks-default-deny\n")
	return sb.String()
}

func (b darwinBackend) CurrentPolicy(run Runner) (string, error) {
	out, err := run.Run("pfctl", "-s", "info")
	if err != nil {
		return "pf-disabled", nil
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(strings.ToLower(strings.TrimSpace(line)), "status: enabled") {
			return "pf-enabled", nil
		}
	}
	return "pf-disabled", nil
}

func (b darwinBackend) Enable(run Runner, spec Spec) error {
	tmp, err := os.CreateTemp("", "veilnet-pf-*.conf")
	if err != nil {
		return fmt.Errorf("firewall: pf anchor file: %w", err)
	}
	name := tmp.Name()
	if _, werr := tmp.WriteString(b.AnchorRules(spec)); werr != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return fmt.Errorf("firewall: pf anchor file: %w", werr)
	}
	_ = tmp.Close()
	defer os.Remove(name)
	if _, err := run.Run("pfctl", "-a", pfAnchor, "-f", name); err != nil {
		return fmt.Errorf("firewall: pf load anchor: %w", err)
	}
	// pf must be enabled for the anchor to filter. Already-enabled
	// firewalls report an error here; that is fine (rules are loaded).
	_, _ = run.Run("pfctl", "-e")
	return nil
}

func (b darwinBackend) Remove(run Runner, names []string) error {
	_, err := run.Run("pfctl", "-a", pfAnchor, "-F", "all")
	_ = names
	return err
}

func (b darwinBackend) SetBlock(run Runner) error {
	// The anchor ends in `block out all`; re-asserting means making sure
	// pf itself is enabled. Rules stay untouched (fail-closed).
	_, _ = run.Run("pfctl", "-e")
	return nil
}

func (b darwinBackend) Restore(run Runner, policy string) error {
	if _, err := run.Run("pfctl", "-a", pfAnchor, "-F", "all"); err != nil {
		return err
	}
	if policy == "pf-disabled" {
		// We enabled pf; put it back the way we found it (never brick).
		_, _ = run.Run("pfctl", "-d")
	}
	return nil
}
