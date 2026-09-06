# SECURITY — DERO // VEILNET

> Scope of this file (DocsTestsDevnet): operator-facing security model —
> exit-node risks, relay mode, secret hygiene, telemetry policy, legal notice.
> Protocol threat model, privacy analysis, and architecture live with their
> owners (`THREAT_MODEL.md`, `PRIVACY.md`, `ARCHITECTURE.md`).

## What VEILNET is (and is not)

- VEILNET is a **decentralized privacy VPN**: a WireGuard data plane with a
  DERO control plane (discovery, auth tokens, payments, receipts).
- **DERO NEVER carries user traffic.** Payments and session tokens are
  control-plane only. Anyone claiming otherwise is describing a different
  system — do not use it.
- There is **no analytics or telemetry**. The client collects no usage data
  and phones home to nobody except the infrastructure you configure
  (your chosen node, DERO daemon/RPC you point it at).
- **No traffic-content logging**: nodes must not log payloads. Anonymous
  aggregate counters (bytes in/out per session, for billing) are the maximum
  any implementation may retain, and only for active sessions.

## Exit-node risks (read before running a node)

Running an exit node means **other people's traffic leaves from your IP**.
Understand this fully:

1. **Legal exposure.** Abuse complaints, DMCA-style notices, and law
   enforcement inquiries go to the exit IP's operator — you. Policies and
   log-minimization do not make you immune.
2. **Egress abuse.** A minority of users will always probe spam, scraping,
   credential stuffing, or worse through exits. Operate rate limits and be
   ready to rotate or retire an exit identity.
3. **No anonymity for the operator.** Your node's endpoint, WireGuard public
   key, region, and bond are public registry metadata by design. Clients pick
   you *because* they can see you.
4. **Compelled operation.** If your jurisdiction can compel logging or
   interception, you must either comply (and disclose) or stop operating.
   Do not silently degrade user safety — shut down cleanly instead.
5. **Payment linkage.** Settlement receipts reference sessions. Keep receipt
   keys on the node only; never publish them, never put them on-chain.

Mitigations built into the protocol (not substitutes for judgment):

- Per-session single-use tokens with expiry; revocation sticks past expiry.
- Node bonds (`bond_dero`) create Sybil cost.
- Local-history-weighted selection lets clients avoid misbehaving exits.
- Kill switch + DNS/IPv6 policy contain client-side leaks (see below).

## Relay mode

Relay (multi-hop) mode routes `client -> entry -> ... -> exit` so no single
node sees both client identity and destination:

- v1 ships **1-hop** (direct to exit). Multi-hop up to **3 hops** is on the
  roadmap (`ROADMAP.md`) with entry-guard pinning.
- Relay circuits use distinct nodes on distinct endpoints; loops and
  same-box hops are rejected at build time
  (`tests/multihop_test.go`, `internal/multihop`).
- Circuit rotation preserves entry hops and swaps the exit, changing exit
  identity without re-exposing the client to new entries.

Relay mode does **not** protect against a global passive adversary, malicious
entry *and* exit collusion, or endpoint correlation (timing/volume). See the
owner's `THREAT_MODEL.md` for the full analysis.

## Client-side leak protection

- **Kill switch:** `OFF` / `ON_WHILE_CONNECTED` (default) / `ALWAYS_ON`.
  `ALWAYS_ON` blocks direct egress even with the tunnel down.
- **DNS:** `VEILNET` (default) / `CUSTOM` / `DOH` / `SYSTEM` (explicit opt-in
  only — the client must refuse silent downgrades to LAN/DHCP resolvers).
- **IPv6:** routed securely through the tunnel or blocked. There is no
  "allow direct IPv6" mode: an unrouted v6 path is a leak, treated as one.
- Integration tests (`tests/integration`) verify exit-IP change, DNS path,
  reconnect, and kill-switch blocking against the devnet. They **fail loudly
  on observed leaks** and **skip as "unverified"** when fixtures are absent —
  a skip is never a pass.

## Secret hygiene (binding)

- **Never auto-spend DERO.** Every transfer requires explicit user approval
  in the client. Mock/dev approvals (`DEV-` prefix) are worthless by
  construction and can never settle on mainnet.
- **Never put secret keys on-chain.** Tokens, receipt keys, WireGuard
  private keys, and wallet seeds travel out-of-band only. Receipts carry an
  HMAC tag, never the key.
- **IPC auth:** the service token file (`~/.veilnet/service.token`, 32 random
  bytes hex, owner-only permissions) guards the Windows named pipe
  (`\\.\pipe\veilnet-service`) or loopback TCP fallback. A corrupt token
  file is refused, never silently regenerated mid-session.
- **Testnet/devnet separation:** dev state lives in `.veilnet-dev/`, never
  `~/.veilnet`. Devnet images refuse `--mainnet`/`MAINNET=1`; mock ids carry
  a `DEV-` prefix. See `docs/DEVNET.md`.

## Operator abuse tooling

Exit operators get rate limiting, a persistent blocklist, a privacy-safe
complaint log, key rotation, and an opt-in auto-disable trigger. Full
audit trail: `docs/AUDIT.md`.

- **Rate limits (per-IP token buckets, fail-open):** authorize attempts
  (default 8/min) and management-API requests (default 60/min).
  Exhaustion returns `429 Too Many Requests` (`ErrRateLimited`); floods
  never fail closed on restart (buckets are in-memory).
- **Blocklist (persistent):** operator IP/pubkey bans in
  `~/.veilnet-node/blocklist.json` (0600), surviving restarts:
  `veilnet-node blocklist (list|block-ip|unblock-ip|block-key|unblock-key) [VALUE]`.
  Blocked peers get `429` (`ErrBlocked`). Restart the daemon after CLI
  changes (the running daemon loads the file once at startup).
- **Complaint log (privacy-safe):** `complaints.jsonl` records reporter,
  timestamp, reason, and action ONLY — never traffic content, DNS names,
  URLs, or counters:
  `veilnet-node report-abuse --reporter R --reason R [--action A] [--ip IP]`.
- **Key rotation:** `veilnet-node rotate-keys` writes a fresh WireGuard
  private key to the config and prints the new pubkey for registry
  re-registration; restart the daemon to use the new identity.
- **Emergency auto-disable (default OFF):** `veilnet-node run
  --abuse-autodisable [--abuse-threshold N]` (or `abuse.json` policy for
  the CLI path) flips `EmergencyDisable` after N complaints (default 5),
  emits `ABUSE_AUTODISABLE`, and logs loudly. The operator must persist
  and review: check `complaints.jsonl`, then re-enable deliberately.

## Reporting vulnerabilities

See `CURRENT_LIMITATIONS.md` for known gaps. For new issues, open a private
report to the maintainers (no public PoC before a fix is available). Do not
probe other operators' mainnet nodes without consent.

## Legal notice

VEILNET software is provided as-is for lawful privacy use. Operating
infrastructure may create obligations in your jurisdiction (data retention,
interception, licensing, tax on node income). Nothing in this repository is
legal advice. Exit-node operation in particular should be preceded by
independent legal review. Comply with applicable law; where compliance
conflicts with user safety, prefer shutting down over silent cooperation.
