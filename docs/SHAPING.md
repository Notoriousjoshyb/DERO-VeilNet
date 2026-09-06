# Traffic shaping and entry transports

> Scope: `internal/cover` (padding and constant-rate cover traffic) and
> `internal/transport` (the pluggable entry-transport seam). Roadmap v2.1.
>
> Rule for this whole area: **measured, never oversold.** Every claim
> below is bounded by what the code actually does.

## Cover traffic (`internal/cover`)

Off by default. It trades real bandwidth for a narrow, specific gain, and
the user makes that trade explicitly.

| Mode | Hides | Does not hide | Cost |
| ---- | ----- | ------------- | ---- |
| `OFF` | nothing | — | none (default) |
| `PAD` | packet **sizes** (bucketed) | timing, volume, direction | padding bytes only |
| `CONSTANT` | size **and** timing, while the link keeps up with the rate | long-window volume, anything above the tunnel | a full cell every interval, capped by `max_overhead` |

### What it does not defend against

- A **global passive adversary** watching both ends. Out of scope for
  VeilNet, permanently. See `docs/THREAT_MODEL.md`.
- Traffic confirmation over long observation windows.
- Application-layer behaviour: what you log into, when, and how often.

### Config (`~/.veilnet/config.toml`)

```toml
[cover]
mode            = "OFF"    # OFF | PAD | CONSTANT
cell_size_bytes = 1024     # CONSTANT only
interval_ms     = 20       # CONSTANT only
max_overhead    = 0.5      # cap wasted bandwidth at 50% of real bytes; 0 = uncapped
```

`CONSTANT` with no `cell_size_bytes` or no `interval_ms` is a config
error, not a silent downgrade to `OFF`: you asked for protection and must
be told it was not applied.

### Measured cost

`Shaper.Stats()` reports `RealBytes`, `PadBytes`, `CoverBytes`,
`CoverCells`, `DroppedOver` and `Overhead()`. Cover cells skipped by the
overhead cap are **counted**, not hidden — a capped shaper protects less,
and the numbers say so. All-cover with no real traffic reports `+Inf`
overhead, which is the honest number.

Design notes kept deliberately:

- A payload larger than the cell rides in its own larger cell rather than
  being truncated. The size leak is visible in the stats instead of being
  papered over.
- `PAD` never grows a packet past the largest bucket (1420 B by default),
  so a padded packet does not fragment.
- A growing `Pending()` queue means the configured rate is too slow for
  the traffic. Surface it; do not hide it.

## Entry transports (`internal/transport`)

WireGuard speaks plain UDP to the entry node, which is easy for a censor
to block. This package is the swappable layer that could carry the same
traffic over something else.

**Honest status: the seam ships; no obfuscating transport does.**

| Transport | Obfuscating | Notes |
| --------- | ----------- | ----- |
| `direct` | no | plain UDP. The default, and the only one built in. |

### Config

```toml
[network]
transport = "direct"
```

An unregistered transport name is a **hard startup error** listing what
is available. It never falls back to `direct`. A client that believes it
is bridged while actually sending plain UDP is worse than one that
refuses to start.

`veilnet --setup` prints the active transport and whether it actually
obfuscates.

### Adding a transport

Implement `transport.Transport` and `Register` it from an `init`:

```go
type myBridge struct{}

func (myBridge) Name() string        { return "my-bridge" }
func (myBridge) Description() string { return "carries WireGuard over ..." }
func (myBridge) Obfuscating() bool   { return true }   // only if it really does
func (myBridge) NewBind(endpoint string) (conn.Bind, error) { ... }

func init() { transport.Register(myBridge{}) }
```

`NewBind` returns a `conn.Bind`, which is the seam wireguard-go already
exposes, so a transport can re-frame packets without the tunnel engine
knowing. Duplicate names panic at registration: two transports answering
to one config value is a state the user cannot reason about.

`Obfuscating()` must not return true unless the transport genuinely
changes what a censor sees. The UI uses that flag to tell the user
whether they have protection.
