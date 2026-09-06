# CURRENT LIMITATIONS — DERO // VEILNET

> Honest status ledger (DocsTestsDevnet). Updated as work lands. Anything
> here marked "planned" is NOT implemented — do not rely on it.

## Data plane

- **Backend selection automatic.** Kernel WireGuard is probed (Windows
  WireGuardNT service, Linux module) with userspace fallback; the active
  backend is named in tunnel status. Throughput is functional, not yet tuned.
- **Multi-hop live (1–3 hops).** Builder, entry-guard pinning, per-hop
  tokens/quotes, and circuit UI are wired end-to-end and exercised against
  demo nodes (`docs/MULTIHOP.md`); real 3-node anonymity sets depend on
  operator adoption, and cover traffic remains explicitly out of scope.
- **Service enforcement is wired.** `veilnet-service` applies the kill
  switch, DNS mode and IPv6 posture on Connect (`internal/app/enforce.go`
  → `cmd/veilnet-service/enforce.go`) and restores them on Disconnect,
  using the per-OS backends (`internal/firewall`: netsh/nftables+iptables/
  pf; `internal/dns`: NRPT/resolved/scutil; `internal/routing` for the
  IPv6 block). Enforcement is **fail-closed**: if it cannot be applied
  the tunnel is torn back down rather than reported PROTECTED, and a
  crashed previous run is cleaned up at service start. A client running
  *without* the privileged service reports `enforcement: not enforced
  here` in Diagnostics — config-state only, and it says so. Full-matrix
  live OS verification is still pending (see `docs/TESTING.md`).
- **Cover traffic is off by default.** `internal/cover` implements `PAD`
  (sizes) and `CONSTANT` (size + timing while the link keeps up) with
  measured overhead. Neither defends against a global passive adversary.
  See `docs/SHAPING.md`.
- **No obfuscating entry transport ships.** `internal/transport` is the
  seam; `direct` (plain UDP) is the only registered transport. An unknown
  name is a hard startup error, never a silent fallback.
 - **Reconnect policy is best-effort.** Session survival across tunnel bounce
   is tested at the session layer; aggressive NAT/captive-portal roaming is
   not yet battle-tested on Windows 11.

## Control plane

- **Registry distribution is file-backed + in-memory** in this milestone;
  full on-chain/SC mirror sync behavior is owned by `internal/registry` and
  may lag this doc — check the code.
- **Payments are prepaid approval-split against DevMock in devnet.**
  Mainnet settlement flow exists in design (`docs/PAYMENTS.md` owner) — do
  NOT run mainnet billing against this build.
- **DERO daemon connectivity** requires a synced daemon or trusted RPC you
  configure; chain freshness is enforced (`ErrDeroUnavailable`), so stale
  daemons refuse rather than mis-settle.

## Platform

- **Windows 11 first.** Linux/macOS are portable targets: control-plane code
  is cross-platform Go, but firewall/DNS/IPv6 enforcement paths are being
  validated per-OS. Silent-leak behavior on a new OS is a release blocker,
  never a known-issue footnote.
- **Installers.** `scripts/package.ps1` (Windows) always produces a
  versioned `.zip` and produces an MSI when WiX v3 is installed **and**
  the version is a numeric `MAJOR.MINOR.PATCH` (an MSI cannot carry
  `0.1.0-dev`). `scripts/package.sh` covers tar/deb/rpm/zip. Missing
  tooling is a clear skip, never a silent partial package.

## Testing gaps (being closed)

- Live kill-switch enforcement needs OS route/firewall fixtures; the unit
  decision surface is fully tested and the integration test **fails on
  observed leaks**, but full-matrix OS coverage is pending — see
  `docs/TESTING.md`.
- Driver-backed persistence is covered: `tests/persist_test.go` (SQLite
  migrations/durability) and `tests/toml_test.go` (config decode/defaults)
  run against the real drivers pinned in `go.mod`.

## Security posture

- Mobile: the OS VPN-permission handshake is implemented and unit-tested
  (`mobile/veilnet/permission.go`); `Start` refuses without a granted
  tunnel handle. On-device validation, background-service behaviour and
  battery remain open work — see `docs/MOBILE.md`.
- No external audit yet. `docs/SECURITY.md` states the model;
  `THREAT_MODEL.md` (owner) states what is NOT defended (global passive
  adversary, entry+exit collusion, endpoint correlation).
- Exit-node operation carries real legal risk — read `docs/SECURITY.md`
  before running one.
