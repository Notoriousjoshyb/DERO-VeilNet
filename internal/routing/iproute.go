package routing

import (
	"fmt"

	"github.com/dero-veilnet/veilnet/internal/platform"
)

func init() {
	platform.Register(platform.KindRoute, linuxBackend{}.Name(), linuxBackend{}.Supports)
}

// linuxBackend manages routes via `ip route`.
type linuxBackend struct{}

func (b linuxBackend) Name() string   { return "ip-route" }
func (b linuxBackend) Supports() bool { return platform.CurrentOS() == platform.Linux }

func (b linuxBackend) Add(run Runner, r Route) error {
	_, err := run.Run("ip", "route", "add", r.Dest, "via", r.Gateway, "dev", r.Iface, "metric", fmt.Sprint(r.Metric))
	return err
}

func (b linuxBackend) Delete(run Runner, r Route) error {
	_, err := run.Run("ip", "route", "del", r.Dest, "via", r.Gateway, "dev", r.Iface)
	return err
}

func (b linuxBackend) SetMetric(run Runner, iface string, metric int) error {
	_, err := run.Run("ip", "link", "set", iface, "metric", fmt.Sprint(metric))
	return err
}

func (b linuxBackend) GetMetric(Runner, string) (int, error) {
	return 0, fmt.Errorf("routing: metric query not supported on linux (restore skipped)")
}

func (b linuxBackend) BlockIPv6(run Runner, tunnelIface string) error {
	_, err := run.Run("ip", "-6", "route", "add", "blackhole", "::/0")
	_ = tunnelIface
	return err
}

func (b linuxBackend) RestoreIPv6(run Runner) error {
	_, err := run.Run("ip", "-6", "route", "del", "blackhole", "::/0")
	return err
}
