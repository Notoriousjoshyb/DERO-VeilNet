package security

import (
	"regexp"
	"strings"
)

// Redaction markers. Keep the prefix stable so log scrapers can match it.
const redacted = "[REDACTED]"

// Patterns for secrets that must never reach logs. Conservative on purpose:
// base64-ish blobs >= 40 chars (WireGuard keys, tokens), 64-hex secrets,
// and explicit key=value forms.
var (
	b64blob  = regexp.MustCompile(`\b[A-Za-z0-9_-]{40,}={0,2}\b`)
	hex64    = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)
	keyValue = regexp.MustCompile(`(?i)\b(private[_-]?key|secret|token|auth|password|psk|presharedkey)\s*[:=]\s*\S+`)
)

// Redact replaces probable secrets in a log line with [REDACTED].
// Private keys, session tokens, and auth material must pass through here
// before any log/event write. Public values (node ids, endpoints, regions)
// are preserved so diagnostics stay useful.
func Redact(s string) string {
	s = keyValue.ReplaceAllString(s, "$1="+redacted)
	// Preserve obvious non-secrets the blob pattern would catch: endpoint
	// host:port and version strings are handled by callers keeping them out
	// of free text; here only exempt dotted quads from b64 redaction.
	s = b64blob.ReplaceAllStringFunc(s, func(m string) string {
		if strings.Count(m, ".") >= 2 || strings.Count(m, "-") > 8 {
			return m
		}
		return redacted
	})
	s = hex64.ReplaceAllString(s, redacted)
	return s
}
