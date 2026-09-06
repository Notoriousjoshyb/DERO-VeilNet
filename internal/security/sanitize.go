package security

import "strings"

// allowedMetadata is the allowlist of node/registry metadata keys that may
// be displayed, logged, or forwarded to the selection engine. Everything
// else is dropped: free-form operator notes are the classic path by which
// contact details, hostnames, or customer identifiers leak into logs and
// on-chain-adjacent records.
var allowedMetadata = map[string]bool{
	"node_id":            true,
	"wg_pubkey":          true,
	"region":             true,
	"country":            true,
	"city":               true,
	"endpoint":           true,
	"price_per_hour_dero": true,
	"capacity_max_clients": true,
	"protocol_version":   true,
	"bond_dero":          true,
	"status":             true,
	"version":            true,
}

// SanitizeMetadata returns a copy containing only allowlisted keys with
// trimmed values. Disallowed keys are dropped silently; over-long values
// (>256 runes) are truncated to bound log/registry growth.
func SanitizeMetadata(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if !allowedMetadata[strings.ToLower(k)] {
			continue
		}
		v = strings.TrimSpace(v)
		if len([]rune(v)) > 256 {
			v = string([]rune(v)[:256])
		}
		out[k] = v
	}
	return out
}
