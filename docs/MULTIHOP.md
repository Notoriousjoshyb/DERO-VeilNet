# VeilNet Multihop Circuits

VeilNet routes traffic through 1–3 independent nodes before it reaches
its destination. Each hop is a separate WireGuard segment run by a
separate operator on a separate machine. This document states what each
hop can observe, why the entry guard stays pinned, and how multi-hop
billing works.

## Topologies

| Hops | Path | When |
|------|------|------|
| 1 | client → node → destination | Fallback only: fewer than two suitable nodes exist. The UI badges this distinctly — it offers no separation. |
| 2 | client → ENTRY → EXIT → destination | Default. Separation of WHO from WHERE. |
| 3 | client → ENTRY → MIDDLE → EXIT → destination | Full separation: no single hop below the client sees both ends. |

A 2-hop circuit is never reported as 3-hop. Rotation never silently
downgrades or upgrades the hop count.

## What each hop observes

These statements are normative — UI copy and docs must never claim a
hop learns less than stated here. (Machine-readable form:
`multihop.Exposures()`.)

**ENTRY** (2-hop and 3-hop):

- Sees the client's real IP address (it terminates the client's
  WireGuard segment), that the client uses VeilNet, and timing + volume
  of encrypted cells.
- Sees the next hop's identity/endpoint (EXIT in 2-hop, MIDDLE in 3-hop)
  because it forwards chained cells there.
- Does NOT see the final destination (host, path, query) or payload
  content: the inner layer is encrypted to the EXIT.

**MIDDLE** (3-hop only):

- Sees NEITHER end. Its only peers are ENTRY and EXIT; cells are doubly
  encrypted. It learns timing + volume and nothing else.
- Does NOT know WHO (client IP stays behind the entry) nor WHERE
  (destination stays inside the exit layer).

**EXIT** (2-hop and 3-hop):

- Sees the previous hop's identity (its WireGuard peer), timing + volume.
- Sees the final destination host and whatever plaintext the app protocol
  itself exposes (e.g. TLS SNI/IP for HTTPS; full content only on
  unencrypted protocols).
- Does NOT see the client's real IP: the outer source is the previous hop.

**Single-hop fallback:** the lone node sees BOTH the client IP and the
destination. Rotate to 2-hop as soon as nodes are available.

Any single malicious hop learns at most one end. Linking client to
destination needs ENTRY+EXIT collusion (or a global observer watching
both segments) — the 3-hop middle adds one more independent party that
must collude. See `docs/THREAT_MODEL.md`.

## Entry guards: why the entry stays pinned

Every rotation is a tradeoff: a fresh exit changes who sees the
destination, but a fresh *entry* exposes the client's real IP to a new
observer. An adversary running many nodes gets a fresh chance to watch
the client on every entry rotation.

VeilNet therefore pins the entry as a **guard**:

- The first hop of a built circuit becomes the sticky guard
  (`GuardPinned: true`, `GuardSince` recorded).
- `RotateCircuit` swaps the exit — or middle+exit on 3-hop routes —
  and never the entry while pinned. The client IP stays behind the same
  entry across rotations.
- Guard lifetime defaults to **30 days**
  (`multihop.DefaultGuardRotationInterval`). A guard older than that is
  *eligible* for replacement, never silently swapped: replacement goes
  through an explicit rebuild, and the UI shows guard status
  (pinned entry id) on the circuit screen.
- **Manual reset** ("Reset guard" button, `POST /api/guard`) clears the
  pin: the next rotation or rebuild may select a fresh entry. Use it when
  the guard is slow, suspect, or due.

Unpinned mode (no guard, e.g. fresh client before the first build) may
rotate the full path.

## Route guards (construction rules)

Every 1–3 hop path is validated before use, and re-validated before
programming the data plane:

1. **Loop rejection** — hop node IDs must be pairwise distinct.
2. **Same-box rejection** — hops must run on distinct machines, checked
   two ways: distinct endpoint hosts (same IP under different ports is
   still one box) and distinct operator keys (WireGuard public keys).
3. **Per-hop latency budget** — the fast/safe tradeoff knob:
   - `fast`: 150 ms per-hop cap, lowest-latency nodes picked first.
     Best for interactive use.
   - `balanced` (default): no cap, blended score
     (latency / load / price / uptime / local history).
   - `safe`: 800 ms cap, distinct countries preferred per hop.
     Tolerates slower nodes to gain separation.
   - An explicit `MaxLatencyMs` overrides the preset. Unmeasured nodes
     are never rejected by budget — absence of signal never blocks.
   - Rejections name the node, its RTT, and the fix (safe tradeoff or a
     faster node).

Violations fail the build with an error naming the fix — there is no
fallback substitution that would mislabel the result.

## Per-hop session tokens

Each hop carries its own token scoped to `(route, node, role)`:
entry / middle / exit (or `single` on 1-hop routes). Tokens are
independent random values: compromising one exposes no other hop.

Exit rotation re-issues **only the exit token** (`ReissueExitToken`):
the stored entry token is never re-minted, so the client is never
re-exposed to a new entry. Token lifetimes default to 24 h.

## Billing math: one approval for the whole circuit

Each hop charges pro-rata: `hop amount = hop price/h × hours`.
The circuit quote sums the shares:

```
Quote{HopQuotes: [{node, role, price/h, hours, amount}...],
      Total: Σ amounts,
      SingleApproval: true}
```

The user approves **once** for the `Total` (`MultiHopApproval` embeds a
single `ApprovalPayload` covering the whole path, with the per-hop
breakdown attached for display). There is never one prompt per hop, no
per-packet transaction, and — as everywhere in VeilNet — no auto-spend:
REJECT aborts before any chain read or funding. Free hops (price 0)
quote 0 but still appear, so the approval always shows the full path.

Example: 3 hops at 0.05 DERO/h for 4 h → 0.20 + 0.20 + 0.20 = **0.60
DERO total**, one dialog.

## Rotation summary

| Action | Entry | Middle | Exit |
|--------|-------|--------|------|
| `RotateCircuit` (pinned) | kept | kept (3-hop) | fresh |
| Downstream rotation (3-hop) | kept | fresh | fresh |
| Full rebuild (unpinned/reset) | may change | may change | fresh |
| `RotateEntry` (guard replacement) | fresh | kept | kept |

Every rotation rebuilds, re-verifies (loop + same-box + budget), and
publishes `CIRCUIT_ROTATED` with hop countries before the UI updates.
If verification fails, the old circuit stays active — rotation never
leaves the client on a half-built path.
