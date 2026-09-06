# VeilNet Threat Model

Scope: the VeilNet client, the local service, exit/entry nodes, and the
DERO control plane. DERO carries **control messages only** (node registry,
bonds, session authorization, payments) and **never user traffic**; bulk
traffic flows over WireGuard segments managed by the tunnel engine.
Secret keys are never placed on-chain. Spending DERO always requires
explicit user approval.

Wording rule: VeilNet reduces exposure; it does not promise anonymity.
The words ANONYMOUS, UNTRACEABLE, and 100% PRIVATE (or equivalents) must
not appear in UI, docs, or diagnostics. Highest allowed claim is
"protected" scoped to a component and check state.

## Actors (15)

Each actor lists what VeilNet **protects against** and what it
**does NOT protect against**. The non-protections are load-bearing: do not
trim them into vaguer language.

### 1. Local-network passive observer (cafe Wi-Fi, LAN sniffer)
- Protects: payload content and destinations are encrypted inside the
  WireGuard segment to the entry; DNS goes through the tunnel by default
  (VEILNET mode), so names are not visible on the LAN.
- Does NOT protect: that you are using VeilNet (WireGuard framing to a
  known entry endpoint is visible), nor timing/volume of your traffic.

### 2. Internet service provider (client side)
- Protects: same as (1) — destinations, DNS (default mode), and content
  are hidden behind the encrypted entry segment.
- Does NOT protect: metadata that you use a VPN-like service, session
  timing/volume, or your real IP (necessarily exposed to the entry node).

### 3. Malicious or compelled ENTRY node
- Protects: final destinations and payload content stay hidden inside the
  inner layer encrypted to the exit; exit identity can be rotated.
- Does NOT protect: your real IP address (the entry terminates your
  segment), your usage timing/volume, or — if it logs — a record that you
  connected. A malicious entry that also observes the exit segment can
  attempt correlation (see 6).

### 4. Malicious or compelled EXIT node
- Protects: your real IP (the exit's peer is the entry, never you);
  inner payload stays protected whenever the app protocol is encrypted
  (HTTPS/TLS).
- Does NOT protect: destinations you visit through it, any plaintext the
  app protocol itself exposes (plain HTTP, DNS outside the tunnel), or
  timing/volume it observes. A malicious exit can serve altered plaintext
  on unencrypted protocols. Prefer encrypted protocols end-to-end.

### 5. DERO chain observer (public ledger reader)
- Protects: user traffic never touches DERO; sessions reveal no content,
  destinations, or client IPs on-chain. Only control artifacts
  (registry entries, bonds, authorization/payment records) are visible.
- Does NOT protect: control-plane metadata that IS on-chain (node
  endpoints, prices, bonds, payment amounts/timing) or linkage between a
  funding wallet and the sessions it pays for. Fund control wallets with
  operational separation in mind.

### 6. Traffic-correlation analyst (observes entry AND exit segments)
- Protects: content and DNS (default mode) remain encrypted; no
  identifiers link the two segments by design.
- Does NOT protect: against timing/volume correlation. An adversary with
  visibility into both segments (or colluding entry+exit) can statistically
  link client and destination. This is an inherent limit of low-latency
  multi-hop designs, not a bug: VeilNet reduces exposure, it does not
  break correlation.

### 7. Global passive adversary
- Protects: raises cost via encrypted segments, entry/exit separation,
  rotation, and default in-tunnel DNS.
- Does NOT protect: against end-to-end correlation given sufficient
  vantage points (superset of 6). No low-latency system claims otherwise.

### 8. Active censor (blocking / DPI middlebox)
- Protects: destination and content hiding inside WireGuard; endpoint
  rotation across regions/endpoints.
- Does NOT protect: recognizability of the WireGuard protocol itself or
  the entry endpoint IP. There is no obfuscation transport in v1; a censor
  that blocks the entry IP/port blocks the circuit.

### 9. DNS resolver / DNS-path observer
- Protects (default VEILNET/DOH modes): queries travel inside the tunnel
  to the configured resolver; LAN/ISP resolvers see nothing.
- Does NOT protect: in SYSTEM-explicit-only mode (user's informed choice)
  the local resolver sees every name; even in tunnel modes the exit-side
  resolver and destination hosts see the resolved names.

### 10. Local IPC / management-service attacker (another user or process)
- Protects: service listens on Windows named pipe
  `\\.\pipe\veilnet-service` (else 127.0.0.1 + 32-byte hex token in
  `~/.veilnet/service.token`), constant-time token compare, mgmt ACL
  (loopback-only default), rate-limited auth, allowlisted commands only.
- Does NOT protect: against an attacker already running as the same user
  who can read the token file — OS user separation is assumed. Never run
  the service and untrusted code as the same user.

### 11. Compromised GUI / front-end supply chain
- Protects: service re-validates every privileged action (token scope,
  ACL, command allowlist); demo mode (`--demo`) is clearly badged and
  never mixes with prod state; backend never auto-spends.
- Does NOT protect: what the GUI displays or silently omits. A
  compromised front-end can mislead the user (fake OK badges, hidden
  warnings). Treat persistent WARNING/FAIL states as authoritative and
  verify the service log independently.

### 12. Compromised host / OS-level malware (keyloggers, memory scrapers)
- Protects: nothing at this layer beyond minimizing secret lifetime
  (keys in memory only, redacted logs, no on-chain secrets).
- Does NOT protect: anything. With host compromise, keys, tokens, traffic
  before encryption, and DERO approval clicks are all exposed. A clean OS
  is a precondition — stated explicitly, not assumed away.

### 13. Node-operator adversary (runs many nodes, selective logging)
- Protects: 2-hop separation (no single honest node sees both ends),
  bond/identity checks, latency/load/price/uptime/history selection that
  spreads load, entry rotation.
- Does NOT protect: against an operator who runs BOTH your entry and exit
  (Sybil concentration) — selection diversity mitigates but cannot
  eliminate this. Distrust concentration: rotate entries and prefer
  distinct operators/regions.

### 14. Supply-chain attacker (dependency / build compromise)
- Protects: Go module pinning, minimal dependency surface, no custom
  crypto (standard WireGuard + TLS + audited libraries only), no
  analytics/telemetry to exfiltrate through.
- Does NOT protect: against a compromised toolchain or dependency below
  the pin. Reproducible builds and dependency review are operational
  requirements, not in-code guarantees.

### 15. Physical device thief (lost laptop / seized machine)
- Protects: DERO spend needs explicit approval per payment (no auto-spend
  to drain); tokens are short-lived, single-use, revocable; logs carry no
  secrets (redactor) so a stolen log disk yields no keys.
- Does NOT protect: data at rest without OS full-disk encryption, or
  unlocked-session abuse. Enable disk encryption and lock/suspend the
  machine; revoke tokens and rotate keys after loss.

## Explicit non-goals (v1)
- Breaking end-to-end timing/volume correlation (actors 6–7).
- Hiding VPN-protocol usage from a network censor (actor 8).
- Security on an already-compromised host (actor 12).
- Private on-chain payments beyond what DERO itself provides (actor 5):
  control metadata on-chain is public by design.
