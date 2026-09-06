// Package multihop builds 1-3 hop privacy circuits: canonical Route
// construction (route.go), entry-guard pinning and guard-aware rotation
// (guards.go, rotator.go), per-hop session tokens and single-approval
// quoting (tokens.go), tradeoff selection (latency.go), and per-hop
// observability contracts (observability.go). See docs/MULTIHOP.md.
package multihop
