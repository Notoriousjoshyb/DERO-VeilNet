//go:build !windows

package main

import "os"

// isAdmin reports whether this process runs as root. Only the service
// install needs elevation; the GUI itself never does.
func isAdmin() (bool, string) {
	if os.Geteuid() == 0 {
		return true, "euid 0"
	}
	return false, "not root"
}

// prereqRunner runs the prerequisite check script.
func prereqRunner() string { return "bash" }

// prereqRunnerPrefix builds runner args before the script path.
func prereqRunnerPrefix() []string { return nil }

// prereqScriptCandidates lists repo-relative check script locations.
func prereqScriptCandidates() []string { return []string{"scripts/setup.sh"} }

// prereqScriptArgs are appended after the script path.
func prereqScriptArgs() []string { return []string{"--check"} }

// prereqLabel names the check for report lines.
func prereqLabel() string { return "scripts/setup.sh --check" }
