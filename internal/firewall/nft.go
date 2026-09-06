package firewall

import (
	"fmt"
	"strings"

	"github.com/dero-veilnet/veilnet/internal/platform"
)

func init() {
	platform.Register(platform.KindFirewall, linuxBackend{}.Name(), linuxBackend{}.Supports)
}

// nftTable is the single table this backend owns. Disable deletes the
// whole table, so no rule can ever linger (zero residual by construction).
const nftTable = "veilnet"

// linuxBackend enforces the kill switch with nftables (preferred) and an
// iptables fallback. Fail-closed semantics mirror the netsh backend:
// handshake UDP + tunnel-local + DHCP/DNS-to-tunnel + optional LAN are
// allowed, everything else drops; on unexpected tunnel loss the rules
// STAY until an explicit Disable.
type linuxBackend struct{}

func (b linuxBackend) Name() string { return "nftables" }
func (b linuxBackend) Supports() bool { return platform.CurrentOS() == platform.Linux }

func (b linuxBackend) RuleNames(spec Spec) []string {
	names := []string{"veilnet-ks-endpoint", "veilnet-ks-tunnel", "veilnet-ks-dhcp"}
	if spec.LANAllowed {
		names = append(names, "veilnet-ks-lan")
	}
	return names
}

func (b linuxBackend) CurrentPolicy(run Runner) (string, error) {
	out, err := run.Run("nft", "list", "table", "inet", nftTable)
	if err != nil {
		// No table (or no nft): the default is open; Disable is a no-op
		// beyond best-effort iptables cleanup.
		return "accept", nil
	}
	if strings.Contains(out, "veilnet-ks-") {
		return "veilnet-drop", nil
	}
	return "accept", nil
}

func (b linuxBackend) Enable(run Runner, spec Spec) error {
	if err := b.enableNft(run, spec); err == nil {
		return nil
	} else {
		// nftables unavailable: fall back to iptables rather than
		// running unprotected. Disable cleans up both paths.
		if ierr := b.enableIptables(run, spec); ierr != nil {
			return fmt.Errorf("firewall: nftables (%v) and iptables (%v) both failed", err, ierr)
		}
		return nil
	}
}

func (b linuxBackend) enableNft(run Runner, spec Spec) error {
	steps := [][]string{
		{"add", "table", "inet", nftTable},
		{"add", "chain", "inet", nftTable, "out", "{", "type", "filter", "hook", "output", "priority", "0", ";", "policy", "drop", ";", "}"},
		{"add", "chain", "inet", nftTable, "in", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "drop", ";", "}"},
		{"add", "rule", "inet", nftTable, "out", "udp", "dport", fmt.Sprint(spec.EndpointPort),
			"ip", "daddr", spec.EndpointIP, "accept", "comment", `"veilnet-ks-endpoint"`},
		{"add", "rule", "inet", nftTable, "out", "ip", "saddr", spec.TunAddr, "accept",
			"comment", `"veilnet-ks-tunnel"`},
		{"add", "rule", "inet", nftTable, "in", "ip", "daddr", spec.TunAddr, "accept",
			"comment", `"veilnet-ks-tunnel"`},
		{"add", "rule", "inet", nftTable, "out", "udp", "dport", "67", "ip", "daddr", "255.255.255.255",
			"accept", "comment", `"veilnet-ks-dhcp"`},
		{"add", "rule", "inet", nftTable, "in", "udp", "sport", "68", "accept",
			"comment", `"veilnet-ks-dhcp"`},
	}
	if spec.LANAllowed {
		steps = append(steps, []string{"add", "rule", "inet", nftTable, "out",
			"ip", "daddr", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
			"accept", "comment", `"veilnet-ks-lan"`})
	}
	for _, args := range steps {
		if _, err := run.Run("nft", args...); err != nil {
			return err
		}
	}
	return nil
}
func (b linuxBackend) enableIptables(run Runner, spec Spec) error {
	commented := func(chain string, rule ...string) error {
		args := append([]string{"-I", chain, "1"}, rule...)
		args = append(args, "-m", "comment", "--comment", "veilnet-ks-fallback", "-j", "ACCEPT")
		_, err := run.Run("iptables", args...)
		return err
	}
	steps := []func() error{
		func() error {
			_, err := run.Run("iptables", "-P", "OUTPUT", "DROP")
			return err
		},
		func() error {
			_, err := run.Run("iptables", "-P", "INPUT", "DROP")
			return err
		},
		func() error {
			_, err := run.Run("iptables", "-I", "OUTPUT", "1", "-p", "udp",
				"-d", spec.EndpointIP, "--dport", fmt.Sprint(spec.EndpointPort),
				"-m", "comment", "--comment", "veilnet-ks-endpoint", "-j", "ACCEPT")
			return err
		},
		func() error { return commented("OUTPUT", "-s", spec.TunAddr) },
		func() error { return commented("INPUT", "-d", spec.TunAddr) },
		func() error {
			_, err := run.Run("iptables", "-I", "OUTPUT", "1", "-p", "udp",
				"-d", "255.255.255.255", "--dport", "67",
				"-m", "comment", "--comment", "veilnet-ks-dhcp", "-j", "ACCEPT")
			return err
		},
		func() error {
			_, err := run.Run("iptables", "-I", "INPUT", "1", "-p", "udp",
				"--sport", "68",
				"-m", "comment", "--comment", "veilnet-ks-dhcp", "-j", "ACCEPT")
			return err
		},
	}
	if spec.LANAllowed {
		for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
			cidr := cidr
			steps = append(steps, func() error { return commented("OUTPUT", "-d", cidr) })
		}
	}
	for _, s := range steps {
		if err := s(); err != nil {
			return err
		}
	}
	return nil
}

func (b linuxBackend) Remove(run Runner, names []string) error {
	// The nft table owns every nft rule: one delete removes them all.
	// iptables fallback rules are removed best-effort (they may never
	// have existed); errors there never mask the nft result.
	_, nftErr := run.Run("nft", "delete", "table", "inet", nftTable)
	for _, n := range names {
		_, _ = run.Run("iptables", "-D", "OUTPUT", "-m", "comment", "--comment", n, "-j", "ACCEPT")
		_, _ = run.Run("iptables", "-D", "INPUT", "-m", "comment", "--comment", n, "-j", "ACCEPT")
	}
	_, _ = run.Run("iptables", "-D", "OUTPUT", "-m", "comment", "--comment", "veilnet-ks-fallback", "-j", "ACCEPT")
	_, _ = run.Run("iptables", "-D", "INPUT", "-m", "comment", "--comment", "veilnet-ks-fallback", "-j", "ACCEPT")
	_ = names
	return nftErr
}

func (b linuxBackend) SetBlock(run Runner) error {
	// Re-assert the drop default: re-declaring the chains with policy
	// drop is idempotent and never touches the allow rules.
	for _, args := range [][]string{
		{"add", "table", "inet", nftTable},
		{"add", "chain", "inet", nftTable, "out", "{", "type", "filter", "hook", "output", "priority", "0", ";", "policy", "drop", ";", "}"},
		{"add", "chain", "inet", nftTable, "in", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "drop", ";", "}"},
	} {
		if _, err := run.Run("nft", args...); err != nil {
			_, _ = run.Run("iptables", "-P", "OUTPUT", "DROP")
			_, _ = run.Run("iptables", "-P", "INPUT", "DROP")
			return err
		}
	}
	return nil
}

func (b linuxBackend) Restore(run Runner, policy string) error {
	if policy == "veilnet-drop" {
		// Previous run already had our table: it was replaced, nothing
		// to restore beyond leaving the (now removed) table gone.
		return nil
	}
	_, err := run.Run("nft", "delete", "table", "inet", nftTable)
	_, _ = run.Run("iptables", "-P", "OUTPUT", "ACCEPT")
	_, _ = run.Run("iptables", "-P", "INPUT", "ACCEPT")
	return err
}
