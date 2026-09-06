# VeilNet Go SDK (beta)

Pure-Go client in `sdk/veilnet`: `Discover`, `Select`, `Quote`,
`Connect` (with `ApproveHook`), `Status`, `Diagnostics`, `Disconnect`.

## Shape

`Client` depends only on small local interfaces — no import cycles:

```go
type Discovery interface{ ListNodes() ([]Node, error) }
type Connector interface {
    Connect(nodeID string) error
    Disconnect() error
}
type Observer interface {
    Observe() (Status, error)
    Diagnose() (Diagnostics, error)
}
type Backend interface { Discovery; Connector; Observer }
type ApproveHook func(q Quote) bool
```

`AppBackend` (in `adapter_app.go`) binds the real `*app.App`; custom
backends implement the interfaces directly.

## Usage

```go
c, _ := veilnet.New(veilnet.Config{
    Region: "eu",
    Approve: func(q veilnet.Quote) bool {
        return q.AmountDERO <= budget, // explicit approval, never auto-spend
    },
}, &veilnet.AppBackend{App: myApp})

nodes, _ := c.Discover()
best, _ := c.Select()          // lowest price, then latency, then id
quote, err := c.Connect("")    // auto-select + approval hook; ErrApprovalDenied on decline
st, _ := c.Status()
diag, _ := c.Diagnostics()
_ = c.Disconnect()
```

Rules: `Connect("")` auto-selects; a named id must exist. Any non-zero
quote runs the hook — nil hook denies all paid connects and allows only
free nodes. Nothing is spent here; settlement stays on the explicit
payments path.

## Conformance

`sdk/conformance_test.go` runs the full flow (Discover → Select →
Quote → Connect → Status → Diagnostics → Disconnect) against fakes
**and** the real app (demo wiring with `FakeEngine`):

```
go test ./sdk/...
```

Plus edge cases: deterministic cheapest-first selection, denied
approval aborts before touching the backend (`ErrApprovalDenied`),
unknown node ids fail.

## Maturity: beta

API is stable for single-hop flows. Multihop/circuit methods are not yet
exposed; `Config` fields may gain options (gap: none reserved yet — new
fields are additive).
