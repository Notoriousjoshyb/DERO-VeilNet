# ROADMAP — DERO // VEILNET

> Scope of this file (DocsTestsDevnet): delivery roadmap. Architecture,
> payments, DERO integration, and node operations details live with their
> owners.

## v1 — working single-hop VPN (this milestone)

- WireGuard data plane via `internal/tunnel` Engine (`DOWN/CONNECTING/UP/FAILED`).
- DERO control plane: registry, prepaid approval-split payments, single-use
  session tokens, node-signed receipts.
- Client app + service + IPC (Windows named pipe; loopback TCP elsewhere).
- Kill switch (`OFF/ON_WHILE_CONNECTED/ALWAYS_ON`), DNS modes
  (`VEILNET/CUSTOM/DOH/SYSTEM-explicit`), IPv6 route-or-block.
- Wails UI (vanilla HTML/CSS/JS, dark charcoal/violet/cyan), `--demo` mode
  badged and isolated from prod state.
- Devnet (`deploy/`) + unit/security/integration suites (`tests/`).

## v1.1 — hardening (landed 2026-09-06)

- Kernel WireGuard probes on Windows (WireGuardNT service) / Linux (module)
  with automatic userspace fallback; active backend named in tunnel status
  (`internal/tunnel`, `internal/platform`).
- Independent-style audit of token/billing/settlement paths with fixes and
  regression tests (`docs/AUDIT.md`, `tests/audit/`).
- Packaged installers groundwork: WiX spec, .deb/.rpm/tarball/zip via
  `scripts/package.sh`, reproducible builds (`docs/PACKAGING.md`).
- Exit-operator abuse tooling: authorize/mgmt rate limits, persistent
  blocklist, privacy-safe complaint log, key rotation, opt-in auto-disable
  (`veilnet-node rotate-keys|report-abuse|blocklist`).
- Service-enforced leak protection: the privileged service applies kill
  switch, DNS mode and IPv6 posture on Connect and restores them on
  Disconnect (`internal/app/enforce.go`, `cmd/veilnet-service/enforce.go`).
  Fail-closed — a tunnel whose protection cannot be applied is torn down,
  never reported PROTECTED. Stale rules from a crash are cleared at
  service start. Diagnostics gained an `enforcement` check that says
  plainly when a client is config-state only.
- Windows packaging script (`scripts/package.ps1`): versioned `.zip`
  always, MSI when WiX v3 and a numeric version are both present, plus
  SHA256SUMS.

## v2 — multi-hop relay, up to 3 hops (landed 2026-09-06)

- Circuit builder: 1–3 distinct nodes, distinct endpoint hosts, distinct
  operator keys; loop/same-box/latency-budget rejections name the fix
  (`internal/multihop/route.go`, `docs/MULTIHOP.md`).
- Entry-guard pinning: sticky entry (30d default, manual reset via
  `/api/guard`); rotation swaps exit/middle only while pinned.
- Per-hop layered session tokens; exit rotation re-issues the exit token
  without re-exposing the client to a new entry.
- Per-hop pro-rata quotes under one user approval
  (`internal/payments/multihop.go`); settlement per hop via idempotent
  `RecordSettlementIdem` batches.
- `CIRCUIT_ROTATED` carries hop countries; circuit screen shows the chain,
  per-hop prices, guard badge. NOTE: payload changed from plain string to
  `CircuitRotated{Path,Hops,Countries,Rotations,GuardPinned}` — external
  string subscribers must update.

## v2.1 — relay polish (in progress)

- **Landed:** cover-traffic shaping (`internal/cover`): `PAD` buckets
  packet sizes, `CONSTANT` emits fixed cells on a fixed interval with an
  overhead cap. Off by default, fully measured (`Stats.Overhead()`,
  skipped cells counted). Global-adversary protection stays explicitly
  out of scope. See `docs/SHAPING.md`.
- **Landed:** pluggable entry-transport seam (`internal/transport`) with
  the `direct` transport, config key `network.transport`, `--setup`
  reporting, and hard failure on an unknown name.
- **Open:** an actual obfuscating/bridge transport. The seam exists; no
  censorship resistance is claimed or shipped.
- (Done via v2: multihop billing as per-hop pro-rata quotes, single approval.)

## v3 — network maturity (landed 2026-09-06, beta)

- Decentralized reputation: slashable-vs-advisory evidence, offline
  verification, signed gossip, bond-aware scoring (`internal/reputation/`,
  `docs/REPUTATION.md`). No subjective global-kill.
- Mobile clients: gomobile-safe library reusing the same control plane
  (`mobile/`, `docs/MOBILE.md`). OS VPN-permission wiring landed
  (`RequestPermission`/`SetTunnelFD`/`GrantTunnel`/`ClearTunnel`); `Start`
  refuses without a granted tunnel handle, so a mobile client can never
  report a connection it cannot carry. On-device validation,
  background-service behaviour and battery remain open work.
- Third-party client SDK with conformance suite (`sdk/`, `docs/SDK.md`).

## Non-goals (will not build)

- Traffic-content inspection or "trust scoring" of destinations.
- Analytics, telemetry, or usage collection of any kind.
- Custodial wallets or auto-spend: explicit approval stays mandatory.
- Carrying user traffic over DERO itself — DERO is control plane only, forever.
