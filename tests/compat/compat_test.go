// Compat tests: docs/COMPATIBILITY.md must contain only actually-executed
// results. This file pins the doc's structure (matrix coverage, evidence
// per PASS, reproduce commands, gaps with owners) so future edits cannot
// silently add faked results.
package compat_test

import (
	"os"
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

func compatDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "COMPATIBILITY.md"))
	if err != nil {
		t.Fatalf("docs/COMPATIBILITY.md missing: %v", err)
	}
	return string(data)
}

var matrixTargets = []string{
	"windows/amd64", "linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64",
}

var matrixBinaries = []string{"veilnet", "veilnet-service", "veilnet-node"}
func TestCompatDocCoversMatrix(t *testing.T) {
	doc := compatDoc(t)
	for _, bin := range matrixBinaries {
		if !strings.Contains(doc, bin) {
			t.Fatalf("COMPATIBILITY.md missing binary %q", bin)
		}
	}
	for _, section := range []string{"## Build matrix", "## Reproduce", "## Limitations", "## Gaps"} {
		if !strings.Contains(doc, section) {
			t.Fatalf("COMPATIBILITY.md missing section %q", section)
		}
	}
}

func TestCompatMatrixEvidence(t *testing.T) {
	doc := compatDoc(t)
	rows := 0
	for _, line := range strings.Split(doc, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			continue
		}
		hasTarget := false
		for _, target := range matrixTargets {
			if strings.Contains(line, target) {
				hasTarget = true
			}
		}
		if !hasTarget {
			continue
		}
		rows++
		upper := strings.ToUpper(line)
		switch {
		case strings.Contains(upper, "PASS"):
			// A PASS is only honest with in-row evidence (command/suite + date).
			if !strings.Contains(line, "go build") && !strings.Contains(line, "go vet") &&
				!strings.Contains(line, "WSL") && !strings.Contains(line, "journey test") &&
				!strings.Contains(line, "platform suite") {
				t.Fatalf("PASS without evidence in row: %s", line)
			}
			if !strings.Contains(line, "2026-") {
				t.Fatalf("PASS without execution date in row: %s", line)
			}
		case strings.Contains(upper, "FAIL"), strings.Contains(upper, "UNTESTED"), strings.Contains(upper, "SKIP"):
			// Honest non-results, allowed with a reason elsewhere in the doc.
		default:
			t.Fatalf("matrix row has no verdict (PASS/FAIL/UNTESTED/SKIP): %s", line)
		}
	}
	want := len(matrixTargets) * len(matrixBinaries)
	if rows < want {
		t.Fatalf("matrix rows = %d, want >= %d (every binary x every target)", rows, want)
	}
}

func TestCompatGoDirectiveMatches(t *testing.T) {
	root := repoRoot(t)
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	var directive string
	for _, line := range strings.Split(string(mod), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "go ") {
			directive = strings.TrimSpace(line)
		}
	}
	if directive == "" {
		t.Fatal("go.mod has no go directive")
	}
	if !strings.Contains(compatDoc(t), directive) {
		t.Fatalf("COMPATIBILITY.md must state the module %q it was built against", directive)
	}
}

func TestCompatCmdInventory(t *testing.T) {
	root := repoRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "cmd"))
	if err != nil {
		t.Fatal(err)
	}
	doc := compatDoc(t)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if !strings.Contains(doc, e.Name()) {
			t.Fatalf("cmd/%s not mentioned in COMPATIBILITY.md", e.Name())
		}
	}
}
