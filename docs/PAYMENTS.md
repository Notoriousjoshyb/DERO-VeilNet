# Payments: Prepaid -> Receipts -> Settlement

DERO funds **session quota**, never packets. The chain sees at most one
funding transfer per grant plus periodic aggregate settlements — there
is no per-packet, per-byte, or per-session transaction. Implemented in
`internal/payments` against `internal/dero` (chain), `internal/tokens`
(bearer auth), and `internal/registry` (price/operator lookup).

## Flow

```text
USER -> PREPAID -> RECEIPTS -> SETTLEMENT
```

### 1. USER: explicit approval

`Service.Authorize(ctx, nodeID, operatorAddr, sessionID, depositDERO)`:

1. Resolves the node from the registry (must be `active`) to get
   `price_per_hour_dero` and `endpoint`. Unknown/inactive nodes abort.
2. Checks unlocked wallet balance covers the deposit. (Wallet-less
   demo skips this: funding is simulated, zero spend possible.)
3. Builds the approval dialog payload — the UI **must** render every
   field and return an explicit verdict:

```json
{
  "node_id": "node-eu-ber-01",
  "endpoint": "203.0.113.10:51820",
  "operator_addr": "deto1operator…",
  "deposit_dero": 2.0,
  "price_per_hour_dero": 0.5,
  "est_hours": 4.0,
  "network": "devmock",
  "wallet_balance_dero": 100.0
}
```

4. `AUTHORISE` proceeds; `REJECT` (or any approver error) aborts with
   `ErrRejected` **before any spend or chain write**. Events
   `PAYMENT_REQUESTED` / `PAYMENT_CONFIRMED` fan out on the bus.

Quota math: `est_hours = deposit / price_per_hour`.
Worked example: **2.0 DERO at 0.5 DERO/hr = 4.0 quota hours**.
Free nodes (`price <= 0`) report `est_hours: -1` (unbounded by payment);
the token TTL still bounds the session (default 4h).

### 2. PREPAID: funding + token

Post-approval, in order:

1. `NewPrepaid` records `{session, node, deposit_atomic, price}`.
2. The funding transfer is **built** (`BuildTransfer`) then
   **submitted** (`SubmitTransfer`) — the submit happens only because
   approval just succeeded, and only on testnet/mainnet. DevMock
   records a synthetic `mock-tx-N`; wallet-less demo records
   `demo-no-wallet`.
3. A bearer token is minted (`tokens.Issuer.Mint`) scoped to the node
   with TTL = quota hours (clamped to `DefaultTTL` when quota is
   unbounded). Token format `<id>.<secret>`: 128-bit id +
   256-bit secret, constant-time validation, single-use revocation.

The client presents the token to the node; the node validates it via
the `tokens.SessionValidator` -> `session.TokenValidator` adapter
(expiry and revocation enforced, forged tokens rejected). **No wallet
seed/key is ever sent to the node** — the token is the only credential
the node sees.

### 3. RECEIPTS: signed usage records

During the session the node counts bytes (counters only — traffic
content is never logged) and periodically signs a `Receipt`:

```json
{
  "id": "rcpt-…", "session_id": "sess-…", "node_id": "node-eu-ber-01",
  "token_id": "…", "rx_bytes": 1048576, "tx_bytes": 262144,
  "minutes": 30, "amount_atomic": 25000, "settled": false,
  "node_pub": "<ed25519 32B>", "sig": "<ed25519 64B>"
}
```

`SignReceipt` (node side, operator key) signs the canonical body;
`RecordReceipt` (client/service side) verifies with `VerifyReceipt`
and stores — bad signatures and duplicate ids are rejected. Receipts
are off-chain; batching them is what keeps the chain quiet.

### 4. SETTLEMENT: one aggregate on-chain call

`Service.RecordSettlement(ctx, nodeID)`:

1. Collects unsettled receipts for the node; empty set aborts.
2. Sums `total` and builds **one** `RecordSettlement(node_id, total,
   count)` contract call (`contracts/veilnet.bas`) via
   `BuildInvoke`/`SubmitInvoke`. No wallet or SCID configured (demo)
   records `demo-no-chain` locally instead.
3. Marks receipts settled and attributes spend to prepaid credit
   (`SpentAtomic`), so `RemainingAtomic` tracks quota burn-down.

Settlement is periodic (operator/cron cadence, e.g. hourly or per N
receipts) — never per packet.

## Demo / DevMock cycle (zero real-DERO spend)

`NewDemoService(registry)` wires mock wallet (100 DERO) + auto
approver + local issuer. Full prepaid -> authorize -> token ->
node-validate -> expiry -> settle cycle runs without a chain:

1. Register a node in `registry.Store` (signed announcement, bond
   meets minimum).
2. `Authorize` 2.0 DERO against it -> grant with token.
3. Validate the token (as the node would) -> OK.
4. Forge (`id.wrong-secret`) / expire (TTL past) -> rejected.
5. Node signs a receipt -> `RecordReceipt` -> `RecordSettlement` ->
   one mock txid, receipts marked settled.

## Invariants

- Never auto-spend: every chain write follows an explicit `AUTHORISE`.
- Never put secret keys on-chain or on the wire to nodes.
- DERO outage fails funding/settlement closed (`RequireFreshChain`)
  but never kills established tunnels — sessions run to token expiry.
- `NeverApprover` is the default: without a wired UI, no spend moves.
