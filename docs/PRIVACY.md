# VeilNet Privacy Policy (engineering binding)

Principle: collect the minimum needed to run the circuit, retain it for
the shortest time that works, and never log traffic content. DERO carries
control messages only — never user traffic. No analytics, no telemetry.

Wording rule: never claim ANONYMOUS, UNTRACEABLE, or 100% PRIVATE. See
docs/THREAT_MODEL.md for what each actor can still observe (correlation,
malicious exit, compromised host).

## Never logged, never stored, never transmitted
- Payload content of user traffic (what you read, type, watch, download).
- Full destination URLs, paths, query strings, or request/response bodies.
- DNS query contents beyond routing them (queries are forwarded, not logged).
- WireGuard private keys, preshared keys, session tokens, service auth
  token contents. Logs pass through the secret redactor
  (internal/security.Redact); key=value secret forms and ≥40-char blobs
  are replaced with `[REDACTED]`.
- Secret keys on-chain: prohibited outright. Nothing in this list is ever
  written to DERO.
- Keystrokes, screen contents, or any analytics/telemetry event stream:
  the client contains no telemetry collector.

## Retained locally (operational minimum)
| Data | Where | Why | Lifetime |
|---|---|---|---|
| Client config (`~/.veilnet/config.toml`), node config (`~/.veilnet-node/config.toml`) | local TOML | reconnect + preferences (kill-switch, DNS mode) | until user deletes |
| Service auth token (`~/.veilnet/service.token`, 32 random bytes hex) | local file, user-only perms | IPC auth | rotated on service reinstall / user request |
| Tokens {id, node_id, session_id, expires_at, scope} + single-use revocation map | service memory (+ node side) | session authorization | until expiry/use, then dropped |
| Node metadata {node_id, wg_pubkey, region, country, city, endpoint, price_per_hour_dero, capacity_max_clients, protocol_version, bond_dero, status, version} | registry cache + sanitized logs | selection (latency/load/price/uptime/history) | cache TTL / operator update |
| Latency aggregates (EWMA RTT per node, sample counts) | memory | entry/exit selection | rolling window, no per-destination data |
| Rotation records {at, old_entry, new_entry, exit_kept, reason} | local diagnostics | show circuit history | session lifetime, then discarded |
| Tunnel stats {rx/tx bytes counters, handshake times} | memory | status + diagnostics | counters reset on circuit rebuild |
| Demo-mode state | memory only, badged | try UI safely | never written to prod config paths |

## Visible on DERO (public by design — control plane only)
Node registry entries, bond records, session authorizations, and payment
records. These contain node dial data, amounts, and timing — never traffic
content, destinations, or keys. Assume a chain observer (threat actor 5)
reads all of it; fund control wallets accordingly.

## Per-hop visibility reminder
- ENTRY sees your real IP, not your destinations (see
  internal/multihop/observability.go EntryExposure).
- EXIT sees destinations, not your real IP (ExitExposure).
- Single-hop fallback sees BOTH — badged distinctly in the UI.
- Colluding entry+exit (or a dual-vantage observer) can correlate
  timing/volume. That residual risk is why absolute claims are forbidden.

## User controls
- Kill switch: OFF / ON_WHILE_CONNECTED / ALWAYS_ON (default ALWAYS_ON
  recommended; diagnostics warn otherwise).
- DNS: VEILNET / CUSTOM / DOH / SYSTEM-explicit-only (SYSTEM requires
  explicit consent; diagnostics flag it WARNING).
- IPv6: routed through the tunnel or blocked — never a silent bypass;
  diagnostics FAIL an unblocked v6 path.
- DERO spend: explicit approval for every payment; the service cannot
  auto-spend.
- Deletion: removing `~/.veilnet/` and `~/.veilnet-node/` plus revoking
  tokens ends local retention; on-chain control records persist per DERO
  semantics and are outside VeilNet's deletion scope.
