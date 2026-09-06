// Package tokens issues single-use auth tokens.
//
// Tokens are 256-bit crypto/rand base64url values with fields
// {id, node_id, session_id, expires_at, scope}; compared in constant
// time; revoked via a single-use revocation map.
//
// Scaffold placeholder: the owning agent implements this package.
package tokens
