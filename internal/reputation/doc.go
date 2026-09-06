// Package reputation is local-only node reputation (beta).
//
// Design rules (binding):
//   - Evidence is SLASHABLE or ADVISORY. Slashable kinds carry proof
//     verifiable offline with ed25519 only (no chain access).
//   - Scores are local. There is no global-kill: a slash finding
//     zeroes the local score and is kept as local evidence; gossip
//     exchanges signed ADVISORY summaries only, never slash verdicts.
//   - Score = f(bond, uptime, local history, slash evidence) with the
//     weights in score.go. Bond and uptime come from the caller
//     (registry/store observations); history and slash come from the
//     local Store.
package reputation
