// setup.sh detection tests: exercise the REAL scripts/setup.sh library
// functions (sourced, never executed) against fixture os-release files and
// a shadowed `command -v` for manager precedence. Complements PackAgent's
// deploy/packaging/tests/test_detect.sh (package lists, live paths); this
// file owns the distro->family mapping and manager-selection precedence.
package platform_test

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// bashSetup returns the bash binary, its drive-mount root, and the
// POSIX-converted setup.sh path, skipping honestly when bash is absent.
func bashSetup(t *testing.T) (bash, mount, setup string) {
	t.Helper()
	var err error
	bash, err = lookupBash()
	if err != nil {
		t.Skipf("unverified: %v", err)
	}
	mount = bashRoot(t, bash)
	setup = bashPath(mount, filepath.Join(repoRoot(t), "scripts", "setup.sh"))
	return bash, mount, setup
}

// setupLib runs a bash snippet with scripts/setup.sh sourced (NOEXEC) and
// returns combined output. Extra env entries are appended to the process env.
func setupLib(t *testing.T, extraEnv []string, snippet string) (string, error) {
	t.Helper()
	bash, _, setup := bashSetup(t)
	script := "VEILNET_SETUP_NOEXEC=1 source " + shellQuote(setup) + "\n" + snippet
	return runBashWith(t, bash, extraEnv, script)
}

func TestDetectDistroFixtures(t *testing.T) {
	_, mount, _ := bashSetup(t)
	cases := map[string]string{
		"os-release.ubuntu":   "ubuntu",
		"os-release.debian":   "debian",
		"os-release.fedora":   "fedora",
		"os-release.rhel":     "rhel",
		"os-release.arch":     "arch",
		"os-release.manjaro":  "arch", // derivative normalizes to family
		"os-release.mint":     "ubuntu",
		"os-release.opensuse": "opensuse-tumbleweed",
		"os-release.alpine":   "alpine",
	}
	for fixture, want := range cases {
		path := bashPath(mount, filepath.Join(repoRoot(t), "tests", "platform", "testdata", fixture))
		out, err := setupLib(t, nil, "veilnet_detect_distro "+shellQuote(path))
		if err != nil {
			t.Fatalf("%s: %v (%s)", fixture, err, out)
		}
		if strings.TrimSpace(out) != want {
			t.Fatalf("%s: distro = %q, want %q", fixture, out, want)
		}
	}

	// Missing file never errors: unknown everywhere, macos on Darwin.
	out, err := setupLib(t, nil, "veilnet_detect_distro /does/not/exist-os-release")
	if err != nil {
		t.Fatalf("missing file must not error: %v (%s)", err, out)
	}
	want := "unknown"
	if runtime.GOOS == "darwin" {
		want = "macos"
	}
	if strings.TrimSpace(out) != want {
		t.Fatalf("missing file: distro = %q, want %q", out, want)
	}
}
// haveShadow overrides `command -v NAME` to consult $FAKE_HAVE (assigned
// inline at the top of the script file) instead of PATH, so manager
// precedence is deterministic on any runner (WSL images ship real apt-get;
// dev boxes ship brew). Non -v uses fail closed. `command` is a shell
// function shadowing the builtin for the duration of the snippet.
const haveShadow = `command() { if [ "$1" = "-v" ]; then case " $FAKE_HAVE " in *" $2 "*) return 0;; *) return 1;; esac; fi; return 1; }
`

func TestDetectPkgManagerPrecedence(t *testing.T) {
	cases := []struct {
		name string
		have string
		want string
	}{
		{"apt", "apt-get", "apt"},
		{"apt-first", "dnf yum apt-get", "apt"},
		{"dnf-beats-yum", "dnf yum", "dnf"},
		{"yum", "yum", "yum"},
		{"pacman", "pacman", "pacman"},
		{"zypper", "zypper", "zypper"},
		{"apk", "apk", "apk"},
		{"none", "", "none"},
	}
	for _, tc := range cases {
		out, err := setupLib(t, []string{"FAKE_HAVE=" + tc.have, "VEILNET_PKG_MANAGER="},
			haveShadow+"veilnet_detect_pkg_manager")
		if err != nil {
			t.Fatalf("%s: %v (%s)", tc.name, err, out)
		}
		if strings.TrimSpace(out) != tc.want {
			t.Fatalf("%s: manager = %q, want %q", tc.name, out, tc.want)
		}
	}

	// Explicit override wins (this is also the brew path on macOS runners).
	out, err := setupLib(t, []string{"FAKE_HAVE=", "VEILNET_PKG_MANAGER=brew"},
		haveShadow+"veilnet_detect_pkg_manager")
	if err != nil {
		t.Fatalf("override: %v (%s)", err, out)
	}
	if strings.TrimSpace(out) != "brew" {
		t.Fatalf("override: manager = %q, want brew", out)
	}
}

func TestPackagesAndInstallCmdShape(t *testing.T) {
	for _, mgr := range []string{"apt", "dnf", "yum", "pacman", "zypper", "apk", "brew"} {
		pkgs, err := setupLib(t, nil, "veilnet_packages_for "+mgr)
		if err != nil {
			t.Fatalf("%s packages: %v", mgr, err)
		}
		for _, need := range []string{"git", "wireguard-tools"} {
			if !strings.Contains(pkgs, need) {
				t.Fatalf("%s packages = %q, must include %q", mgr, pkgs, need)
			}
		}
		got, gerr := setupLib(t, nil, `pkgs="$(veilnet_packages_for `+mgr+`)"; veilnet_install_cmd_for `+mgr+` $pkgs`)
		if gerr != nil {
			t.Fatalf("%s install cmd: %v (%s)", mgr, gerr, got)
		}
		if strings.TrimSpace(got) == "" {
			t.Fatalf("%s must produce a non-empty install command", mgr)
		}
	}
}

func TestSetupCheckContractShape(t *testing.T) {
	bash, mount, _ := bashSetup(t)
	setup := bashPath(mount, filepath.Join(repoRoot(t), "scripts", "setup.sh"))
	out, _ := runBashWith(t, bash, nil, shellQuote(setup)+" --check")
	if !strings.Contains(out, "ok:") && !strings.Contains(out, "missing:") {
		t.Fatalf("--check must print ok:/missing: report lines, got:\n%s", out)
	}
}
