// Shared helpers for the platform suite: repo root discovery, bash
// execution (WSL bash or git-bash on Windows, system bash elsewhere),
// Windows->POSIX path conversion, shell quoting.
package platform_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repo root (go.mod) not found above working dir")
		}
		dir = parent
	}
}

func lookupBash() (string, error) {
	for _, n := range []string{"bash", "sh"} {
		if p, err := exec.LookPath(n); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no bash/sh on PATH (Windows: install Git for Windows or enable WSL)")
}

// bashRoot probes the bash mount layout: WSL bash mounts drives at /mnt/c,
// git-bash at /c.
func bashRoot(t *testing.T, bash string) string {
	t.Helper()
	for _, probe := range []string{"/mnt/c", "/c"} {
		var out bytes.Buffer
		cmd := exec.Command(bash, "-c", "test -d "+probe+" && echo yes")
		cmd.Stdout = &out
		if cmd.Run() == nil && strings.TrimSpace(out.String()) == "yes" {
			return probe
		}
	}
	t.Fatalf("unverified: bash at %q has neither /mnt/c nor /c mounts", bash)
	return ""
}

// bashPath converts an absolute Windows path to POSIX form for the given
// bash mount root (C:\x\y -> /mnt/c/x/y or /c/x/y); POSIX input passes
// through unchanged.
func bashPath(root, p string) string {
	if len(p) < 2 || (p[0] == '/' && !strings.Contains(p, "\\")) {
		return p
	}
	p = strings.ReplaceAll(p, "\\", "/")
	if len(p) >= 2 && p[1] == ':' {
		drive := strings.ToLower(p[:1])
		if strings.HasSuffix(strings.ToLower(root), "/"+drive) {
			return root + p[2:]
		}
		return root + "/" + drive + p[2:]
	}
	return p
}

func runBashWith(t *testing.T, bash string, extraEnv []string, script string) (string, error) {
	t.Helper()
	// NOTE: the script is delivered via a temp FILE, never `bash -c`, and
	// per-test variables are assigned inline at the top of the file.
	// The WSL launcher mangles `$` constructs in `-c` strings and drops
	// custom Windows env vars (no WSLENV); files are immune to both.
	mount := bashRoot(t, bash)
	f, err := os.CreateTemp(t.TempDir(), "veilnet-*.sh")
	if err != nil {
		t.Fatal(err)
	}
 varEnv := ""
	for _, kv := range extraEnv {
		if i := strings.Index(kv, "="); i >= 0 {
			varEnv += kv[:i] + "=" + shellQuote(kv[i+1:]) + "\n"
		}
	}
	if _, err := f.WriteString(varEnv + script); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bash, bashPath(mount, f.Name()))
	cmd.Dir = repoRoot(t)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	runErr := cmd.Run()
	return buf.String(), runErr
}


func runBash(t *testing.T, extraEnv []string, script string) (string, error) {
	t.Helper()
	bash, err := lookupBash()
	if err != nil {
		t.Skipf("unverified: %v", err)
	}
	return runBashWith(t, bash, extraEnv, script)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
