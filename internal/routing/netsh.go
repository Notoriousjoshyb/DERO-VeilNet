package routing

import (
	"fmt"
	"strings"

	"github.com/dero-veilnet/veilnet/internal/platform"
)

func init() {
	platform.Register(platform.KindRoute, windowsBackend{}.Name(), windowsBackend{}.Supports)
}

// windowsBackend manages routes and metrics via netsh.
type windowsBackend struct{}

func (b windowsBackend) Name() string     { return "netsh" }
func (b windowsBackend) Supports() bool   { return platform.CurrentOS() == platform.Windows }

// ipv6RuleName is the firewall rule blocking IPv6 egress.
const ipv6RuleName = "VeilNet-IPv6-Block"

func (b windowsBackend) Add(run Runner, r Route) error {
	_, err := run.Run("netsh", "interface", "ipv4", "add", "route",
		r.Dest, fmt.Sprintf(`"%s"`, r.Iface), r.Gateway, fmt.Sprintf("metric=%d", r.Metric))
	return err
}

func (b windowsBackend) Delete(run Runner, r Route) error {
	_, err := run.Run("netsh", "interface", "ipv4", "delete", "route",
		r.Dest, fmt.Sprintf(`"%s"`, r.Iface), r.Gateway)
	return err
}

func (b windowsBackend) SetMetric(run Runner, iface string, metric int) error {
	_, err := run.Run("netsh", "interface", "ipv4", "set", "interface",
		fmt.Sprintf(`"%s"`, iface), fmt.Sprintf("metric=%d", metric))
	return err
}

func (b windowsBackend) GetMetric(run Runner, iface string) (int, error) {
	out, err := run.Run("netsh", "interface", "ipv4", "show", "interface", fmt.Sprintf(`"%s"`, iface))
	if err != nil {
		return 0, err
	}
	// Best-effort parse; callers ignore errors and skip restore.
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		for i, tok := range f {
			if strings.EqualFold(tok, "metric") && i+1 < len(f) {
				var n int
				if _, serr := fmt.Sscanf(f[i+1], "%d", &n); serr == nil {
					return n, nil
				}
			}
		}
	}
	return 0, fmt.Errorf("routing: metric not found")
}

func (b windowsBackend) BlockIPv6(run Runner, tunnelIface string) error {
	if _, err := run.Run("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ipv6RuleName, "dir=out", "action=block", "remoteip=::/0",
		"description=VeilNet IPv6 leak block"); err != nil {
		return err
	}
	if _, err := run.Run("netsh", "interface", "ipv6", "set", "interface",
		fmt.Sprintf(`"%s"`, tunnelIface), "routerdiscovery=disabled",
		"managedaddress=disabled", "otherstateful=disabled"); err != nil {
		return err
	}
	return nil
}

func (b windowsBackend) RestoreIPv6(run Runner) error {
	_, err := run.Run("netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+ipv6RuleName)
	return err
}
