//go:build windows

package main

import "os/exec"

// isAdmin reports whether this process is elevated. `net session` succeeds
// only for elevated\Admin sessions; anything else means the service install
// step needs an elevated prompt (the GUI itself never needs admin).
func isAdmin() (bool, string) {
	if err := exec.Command("net", "session").Run(); err != nil {
		return false, "net session denied"
	}
	return true, "net session ok"
}

// prereqRunner runs the prerequisite check script.
func prereqRunner() string { return "powershell" }

// prereqRunnerPrefix builds runner args before the script path.
func prereqRunnerPrefix() []string {
	return []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File"}
}

// prereqScriptCandidates lists repo-relative check script locations.
func prereqScriptCandidates() []string {
	return []string{`scripts\setup.ps1`, "scripts/setup.ps1"}
}

// prereqScriptArgs are appended after the script path.
func prereqScriptArgs() []string { return []string{"-Check"} }

// prereqLabel names the check for report lines.
func prereqLabel() string { return "scripts/setup.ps1 -Check" }
