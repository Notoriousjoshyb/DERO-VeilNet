package routing

import (
	"fmt"
	"strings"

	"github.com/dero-veilnet/veilnet/internal/platform"
)

func init() {
	platform.Register(platform.KindRoute, darwinBackend{}.Name(), darwinBackend{}.Supports)
}

// darwinBackend manages routes via BSD `route`. Interface metrics are
// per-route on macOS, so SetMetric is an explicit error, not a silent
// no-op.
type darwinBackend struct{}

func (b darwinBackend) Name() string   { return "bsd-route" }
func (b darwinBackend) Supports() bool { return platform.CurrentOS() == platform.Darwin }

func (b darwinBackend) Add(run Runner, r Route) error {
	if r.Dest == "0.0.0.0/0" {
		_, err := run.Run("route", "-n", "add", "-inet", "default", r.Gateway)
		return err
	}
	_, err := run.Run("route", "-n", "add", "-inet", strings.TrimSuffix(r.Dest, "/32"), r.Gateway)
	return err
}

func (b darwinBackend) Delete(run Runner, r Route) error {
	if r.Dest == "0.0.0.0/0" {
		_, err := run.Run("route", "-n", "delete", "-inet", "default", r.Gateway)
		return err
	}
	_, err := run.Run("route", "-n", "delete", "-inet", strings.TrimSuffix(r.Dest, "/32"), r.Gateway)
	return err
}

func (b darwinBackend) SetMetric(Runner, string, int) error {
	return fmt.Errorf("routing: interface metric not supported on darwin (route metrics per-route)")
}

func (b darwinBackend) GetMetric(Runner, string) (int, error) {
	return 0, fmt.Errorf("routing: metric query not supported on darwin (restore skipped)")
}

func (b darwinBackend) BlockIPv6(run Runner, tunnelIface string) error {
	_, err := run.Run("route", "-n", "add", "-inet6", "::/0", "::1", "-blackhole")
	_ = tunnelIface
	return err
}

func (b darwinBackend) RestoreIPv6(run Runner) error {
	_, err := run.Run("route", "-n", "delete", "-inet6", "::/0", "::1")
	return err
}
