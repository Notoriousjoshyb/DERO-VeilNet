// Platform default tests: config/data dir resolution, service-spec sanity,
// backend probe registry. Host-OS rows execute for real; every other OS row
// is documented in docs/COMPATIBILITY.md and needs a CI runner for that OS
// (owner: CleanQA matrix) — never faked here.
package platform_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/dero-veilnet/veilnet/internal/config"
	"github.com/dero-veilnet/veilnet/internal/platform"
	"github.com/dero-veilnet/veilnet/internal/storage"

	_ "github.com/dero-veilnet/veilnet/internal/dns"
	_ "github.com/dero-veilnet/veilnet/internal/firewall"
	_ "github.com/dero-veilnet/veilnet/internal/routing"
)

// withTempHome isolates os.UserHomeDir for config/storage lookups.
// Windows honors USERPROFILE; Unix honors HOME.
func withTempHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	return home
}

func TestDefaultConfigIsSafeFirstRun(t *testing.T) {
	cfg := config.DefaultClientConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
	if cfg.KillSwitch != config.KillWhileConnected {
		t.Fatalf("killswitch default = %q, want ON_WHILE_CONNECTED (fail-closed first run)", cfg.KillSwitch)
	}
	if cfg.DNS.Mode != config.DNSVeilnet {
		t.Fatalf("dns default = %q, want VEILNET (system resolver is explicit-only)", cfg.DNS.Mode)
	}
	if cfg.DNS.IPv6Upstream {
		t.Fatal("IPv6 upstream must default off: never silently leak IPv6")
	}
	if cfg.AutoConnect {
		t.Fatal("auto-connect must default off: no surprise traffic on first run")
	}
	if cfg.Payments.MaxPerHourDero <= 0 {
		t.Fatal("payment cap must default positive (explicit approval still required)")
	}
	red := cfg.Redacted()
	if red.Dero.RPCPassword != "" && red.Dero.RPCPassword == cfg.Dero.RPCPassword {
		t.Fatal("Redacted must mask secrets before logging")
	}
}

func TestClientVsNodePathsNeverShare(t *testing.T) {
	home := withTempHome(t)
	client, err := config.ClientConfigPath()
	if err != nil {
		t.Fatalf("client path: %v", err)
	}
	node, err := config.NodeConfigPath()
	if err != nil {
		t.Fatalf("node path: %v", err)
	}
	db, err := storage.ClientDBPath()
	if err != nil {
		t.Fatalf("db path: %v", err)
	}
	for _, p := range []string{client, node, db} {
		if !strings.HasPrefix(p, home) {
			t.Fatalf("path %q escapes temp home %q", p, home)
		}
	}
	if client == node {
		t.Fatal("client and node config must never share a file")
	}
	if !strings.HasSuffix(client, filepath.Join(".veilnet", "config.toml")) {
		t.Fatalf("client path = %q", client)
	}
	if !strings.HasSuffix(node, filepath.Join(".veilnet-node", "config.toml")) {
		t.Fatalf("node path = %q", node)
	}
	if !strings.HasSuffix(db, filepath.Join(".veilnet", "client.db")) {
		t.Fatalf("db path = %q", db)
	}
}

func TestMissingConfigYieldsDefaults(t *testing.T) {
	withTempHome(t)
	cfg, err := config.LoadClient("")
	if err != nil {
		t.Fatalf("first run with no config file must work: %v", err)
	}
	def := config.DefaultClientConfig()
	if cfg.KillSwitch != def.KillSwitch || cfg.DNS.Mode != def.DNS.Mode {
		t.Fatalf("missing file must yield defaults, got %+v", cfg)
	}
}

func TestCurrentOSMatchesRuntime(t *testing.T) {
	if string(platform.CurrentOS()) != runtime.GOOS &&
		!(platform.CurrentOS() == platform.Other) {
		t.Fatalf("CurrentOS() = %q, runtime = %q", platform.CurrentOS(), runtime.GOOS)
	}
}

func TestNeedsPrivilegedServiceAlways(t *testing.T) {
	// Raw TUN + firewall + route mutation needs elevation on every OS.
	if !platform.NeedsPrivilegedService() {
		t.Fatal("NeedsPrivilegedService must be true on all supported OSes")
	}
}

func TestDefaultServiceSanity(t *testing.T) {
	spec := platform.DefaultService()
	if spec.Name == "" || spec.Display == "" || spec.Exec == "" {
		t.Fatalf("service spec must be complete, got %+v", spec)
	}
	if !strings.Contains(strings.ToLower(spec.Exec), "veilnet-service") {
		t.Fatalf("service exec = %q, must reference veilnet-service", spec.Exec)
	}
	hint := spec.InstallHint()
	if hint == "" || !strings.Contains(strings.ToLower(hint), "veilnet") {
		t.Fatalf("InstallHint must name the fix, got %q", hint)
	}
	switch platform.CurrentOS() {
	case platform.Windows:
		if spec != (platform.ServiceSpec{Name: "veilnet", Display: "VeilNet Service", Exec: "veilnet-service.exe"}) {
			t.Fatalf("windows spec = %+v", spec)
		}
		if !strings.Contains(hint, "sc create") {
			t.Fatalf("windows hint must use sc, got %q", hint)
		}
	case platform.Linux:
		if !strings.Contains(hint, "systemctl") {
			t.Fatalf("linux hint must use systemctl, got %q", hint)
		}
	case platform.Darwin:
		if !strings.Contains(hint, "launchctl") {
			t.Fatalf("darwin hint must use launchctl, got %q", hint)
		}
	}
}

func TestAppDirsHonorEnv(t *testing.T) {
	home := withTempHome(t)
	dirs := platform.AppDirs()
	switch platform.CurrentOS() {
	case platform.Windows:
		appdata := t.TempDir()
		local := t.TempDir()
		t.Setenv("APPDATA", appdata)
		t.Setenv("LOCALAPPDATA", local)
		dirs = platform.AppDirs()
		if dirs.Config != filepath.Join(appdata, "veilnet") {
			t.Fatalf("config dir = %q", dirs.Config)
		}
		if dirs.Data != filepath.Join(local, "veilnet") {
			t.Fatalf("data dir = %q", dirs.Data)
		}
		if dirs.State != filepath.Join(local, "veilnet", "state") {
			t.Fatalf("state dir = %q", dirs.State)
		}
		// XDG must not leak into Windows resolution.
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
		if got := platform.AppDirs(); got.Config != dirs.Config {
			t.Fatalf("XDG leaked into windows dirs: %q", got.Config)
		}
	default:
		xdg := t.TempDir()
		t.Setenv("XDG_CONFIG_HOME", xdg)
		dirs = platform.AppDirs()
		if dirs.Config != filepath.Join(xdg, "veilnet") {
			t.Fatalf("XDG_CONFIG_HOME not honored: %q", dirs.Config)
		}
	}
	if dirs.Config == "" || dirs.Data == "" || dirs.State == "" {
		t.Fatalf("dirs must be complete, got %+v", dirs)
	}
	if dirs.Config == dirs.State {
		t.Fatalf("config and state must not share a dir: %+v", dirs)
	}
}

func TestAppDirsFallbackWithoutEnv(t *testing.T) {
	withTempHome(t)
	t.Setenv("APPDATA", "")
	t.Setenv("LOCALAPPDATA", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	dirs := platform.AppDirs()
	if dirs.Config == "" || dirs.Data == "" || dirs.State == "" {
		t.Fatalf("fallback dirs must be complete, got %+v", dirs)
	}
	if err := dirs.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	for _, p := range []string{dirs.Config, dirs.Data, dirs.State} {
		if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
			t.Fatalf("Ensure did not create %q: %v", p, err)
		}
	}
}

// expectedBackend is the backend that must report Supported on each OS.
func TestBackendProbesMatchHost(t *testing.T) {
	if got := platform.Supported(platform.KindFirewall, "definitely-not-a-backend"); got {
		t.Fatal("unknown backend names must report false")
	}
	if got := platform.Available(platform.Kind("definitely-not-a-kind")); len(got) != 0 {
		t.Fatalf("unknown kind must list nothing, got %v", got)
	}
	cases := map[platform.Kind]map[platform.OS]string{
		platform.KindFirewall: {
			platform.Windows: "netsh",
			platform.Linux:   "nftables",
			platform.Darwin:  "pf",
		},
		platform.KindDNS: {
			platform.Windows: "netsh-nrpt",
			platform.Linux:   "systemd-resolved",
			platform.Darwin:  "networksetup",
		},
		platform.KindRoute: {
			platform.Windows: "netsh",
			platform.Linux:   "ip-route",
			platform.Darwin:  "bsd-route",
		},
	}
	for kind, want := range cases {
		names := platform.Available(kind)
		if len(names) == 0 {
			t.Fatalf("kind %q lists no backends (subsystem init missing?)", kind)
		}
		host, ok := want[platform.CurrentOS()]
		if !ok {
			t.Logf("unverified: kind %q on %q needs a %s runner (CleanQA matrix)", kind, platform.CurrentOS(), platform.CurrentOS())
			continue
		}
		supported := 0
		for _, n := range names {
			if platform.Supported(kind, n) {
				supported++
				if n != host {
					t.Fatalf("kind %q: backend %q reports supported on %q, want only %q",
						kind, n, platform.CurrentOS(), host)
				}
			}
		}
		if supported != 1 {
			t.Fatalf("kind %q: %d supported backends on %q (%v), want exactly %q",
				kind, supported, platform.CurrentOS(), names, host)
		}
	}
}
