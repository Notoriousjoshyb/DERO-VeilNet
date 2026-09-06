# VeilNet reputation (beta)

Local-only node reputation. Scores never leave the device as verdicts;
only signed **advisory summaries** are gossiped, and each client applies
its own weights. There is no global-kill: a slash finding zeroes the
**local** score and stays local.

## Evidence kinds

| Kind | Class | Proof |
|---|---|---|
| `double-settlement` | SLASHABLE | Two receipts, same ID, distinct bodies, both validly node-signed |
| `forged-receipt` | SLASHABLE | A receipt presented as settled whose node signature does NOT verify |
| `latency` / `uptime` / `downtime` | ADVISORY | Local observation JSON, reporter-signed |

Slash proofs verify **offline** (ed25519 only, no chain access):
a forged proof carrying a *valid* signature is rejected (nothing forged),
and identical receipts are rejected as double-settlement (nothing doubled).
Every evidence record is reporter-signed; tampering fails verification.

## Scoring

```
bondN = min(bondDERO / 100, 1)
score = clamp01(0.30*bondN + 0.30*uptime + 0.40*history)
slashed (verified local SLASHABLE evidence) => 0
```

`history` is the local past-session success rate (0.5 when unknown).
Bond/uptime come from the caller (`SetNodeInfo`); history and slash
state come from the store.

## Store

`Open(path)` persists to a JSON file (atomic temp-write + rename,
`0600`); `Open("")` is in-memory. `Add` verifies before storing —
malformed or adversarial evidence is rejected, never stored.

## Gossip

`Store.Summary` builds a signed `Advisory{node_id, uptime,
avg_latency_ms, samples}`; `Marshal`/`ParseAdvisory` round-trip it with
signature verification. Only ADVISORY summaries are exchanged — never
slash verdicts.

## Registry integration (no registry edits)

```go
import (
    "github.com/dero-veilnet/veilnet/internal/registry"
    "github.com/dero-veilnet/veilnet/internal/reputation"
)
store, _ := reputation.Open("/var/lib/veilnet/reputation.json")
criteria := registry.Criteria{History: reputation.HistoryScore(store)}
node, err := reg.Select(criteria)
```

`HistoryScore` returns a value implementing the `registry.History`
shape (`Score(nodeID) float64`); reputation never imports registry, so
no import cycle is possible. Nil scorer scores `UnknownHistory` (0.5).

## Maturity: beta

Slash verification, scoring, gossip, and persistence are implemented and
tested (`go test ./internal/reputation/...`). Gossip transport (peer
exchange) is not yet wired — summaries are built/verified locally.
