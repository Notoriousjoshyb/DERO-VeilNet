package security

import (
	"errors"
	"strings"
)

// allowedCommands is the closed set of external binaries the management
// plane may invoke. Anything else — shells included — is rejected. There
// is intentionally no shell-escape helper: callers must exec argv directly
// (no sh -c) using these names only.
var allowedCommands = map[string]bool{
	"wg":        true,
	"ip":        true,
	"iptables":  true,
	"ip6tables": true,
	"netsh":     true,
	"resolvectl": true,
}

// ValidateCommand rejects anything outside the allowlist and rejects
// shell metacharacters in every argument. Empty command, absolute-path
// switching ("/bin/wg"), and flag smuggling ("--foo=$(...)") all fail.
func ValidateCommand(name string, args []string) error {
	if !allowedCommands[name] {
		return errors.New("security: command not allowlisted: " + name)
	}
	for _, a := range args {
		if a == "" {
			return errors.New("security: empty argument rejected")
		}
		if strings.ContainsAny(a, ";|&$`\\\"\n\r\x00()<>{}") {
			return errors.New("security: shell metacharacter in argument: " + a)
		}
		if strings.Contains(a, "..") {
			return errors.New("security: path traversal in argument: " + a)
		}
	}
	return nil
}
