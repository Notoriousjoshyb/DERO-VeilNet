# DERO Integration

VeilNet uses DERO as a **control plane only**: node registry writes,
prepaid funding, and periodic aggregate settlement. DERO **never**
carries user traffic, and secret keys are **never** put on-chain.

All method names, ports, and unit rates below come from the
authoritative references listed at the bottom. Anything outside this
surface goes through the explicit `MockAdapter` (`internal/dero/mock.go`)
and fails loudly — no invented RPCs.

## Daemon JSON-RPC

Base: `POST <daemon>/json_rpc`, JSON-RPC 2.0 (`{"jsonrpc":"2.0","id":1,…}`).

| VeilNet use | Method | Returns (fields read) |
|---|---|---|
| Chain height check | `DERO.GetHeight` | `height`, `stableheight`, `topoheight` |
| Chain status display | `DERO.GetInfo` | `height`, `stableheight`, `topoheight`, `network`, `version`, `peer_count` |

Implemented by `HTTPDaemonClient` (`internal/dero/client.go`).
`MockDaemonClient` returns the same shapes with canned values.

Reference ports (examples from the docs; use your node's configured port):

- Daemon examples: `127.0.0.1:10102/json_rpc` (integrations),
  `127.0.0.1:40402/json_rpc` (older docs page).
- VeilNet defaults: testnet/mainnet daemon `127.0.0.1:10102`,
  DevMock daemon `127.0.0.1:19092` (localhost-only, never a real chain).

## Wallet JSON-RPC

Base: `POST <wallet>/json_rpc`. **Localhost only** — never expose the
wallet RPC publicly; remote access requires auth plus a private proxy.

| VeilNet use | Method | Notes |
|---|---|---|
| Balance / funding check | `GetBalance` | returns atomic `balance`, `unlocked_balance` |
| Own address display | `GetAddress` | address string only, never a key |
| Sync sanity | `GetHeight` (wallet) | wallet height |
| Send funding (post-approval) | `transfer` | `destination`, `amount` (atomic), `ringsize: 32`; native DERO uses zero SCID `0000…0000` |
| Registry / settlement calls | `scinvoke` | `scid`, `ringsize: 2`, `sc_rpc` with `entrypoint` (`S`) plus args (`S`/`U`/`H`) |
| Confirm a funding tx | `GetTransferbyTXID` | exact casing; `txid` param |

Wallet reference ports: `127.0.0.1:40403` (Stargate default),
`127.0.0.1:20209` (Atlantis API v2.0 PDF). VeilNet defaults:
testnet/mainnet wallet `127.0.0.1:40403`,
DevMock wallet `127.0.0.1:19093`.

### Units

Stargate wallet examples: **100000 atomic units = 1 DERO**
(`internal/dero`: `AtomicPerDero`, `ToAtomic`, `FromAtomic`).

### Spend discipline

1. `BuildTransfer` / `BuildInvoke` construct **unsigned** payloads —
   no RPC, no spend.
2. The approval dialog (`internal/payments`) renders node, operator
   address, deposit, estimated hours, and network, and returns
   `AUTHORISE` or `REJECT`. `REJECT` aborts before any spend.
3. `SubmitTransfer` / `SubmitInvoke` fire only post-approval, and only
   on testnet/mainnet networks — DevMock submits return synthetic
   `mock-tx-N` ids with zero real spend.
4. Seeds/keys never cross this boundary: the RPC server holds them and
   only txids come back. Wallet material is **never sent to a node**.

## XSWD hook point

For production spend, approval **should** route through the user's own
wallet via XSWD (wallet-to-dApp bridge) or the equivalent wallet
bridge, so confirmation happens in wallet UX — not only in VeilNet's
dialog. `internal/dero/xswd.go` is the seam: `XSWDConnector`
(`Connect` / `RequestTransfer` / `Close`) plus `MockXSWD` for dev.
Direct wallet JSON-RPC stays localhost-bound either way.

## Smart contract (DERO BASIC)

`contracts/veilnet.bas` implements the registry/settlement surface:

- `Initialize`, `RegisterNode`, `UpdateNode`, `DisableNode`,
  `SetPrice`, `DepositBond`, `WithdrawBond`, `RecordSettlement`
  (state-changing, `RETURN 0`/`1`), plus `GetPrice`, `GetStatus`,
  `GetBond` readers.
- State via `STORE` / `LOAD` / `EXISTS`; caller checks via `SIGNER()`;
  address args convert with `ADDRESS_RAW()`.
- `DepositBond` takes an `amount` attestation and is invoked with
  `transfer` + `sc_rpc` so matching value attaches; everything else is
  plain `scinvoke`. No per-packet / per-byte / per-session transaction
  exists by design.

## Network switch

`dero.Network`: `devmock` (default for tests/`--demo`, zero spend) →
`testnet` → `mainnet`. `DefaultEndpoints(n)` returns the URL set.
`MockAdapter` is the boundary for anything unsupported: it errors with
a pointer to this document.

## Outage policy (binding)

A DERO outage **never kills established tunnels.** Transport/RPC
failure surfaces as `ErrDeroUnavailable` (`IsUnavailable`): operations
needing fresh chain truth (prepaid funding, settlement submission,
registry mirror writes) fail closed via `RequireFreshChain`, while
established data-plane sessions continue on existing tokens until
token expiry. `ReportStatus` fans `DERO_CONNECTED` /
`DERO_DISCONNECTED` on the event bus; tunnel code subscribes but must
not tear down live sessions on disconnect.

## Sources

- DERO Stargate RPC API (daemon + wallet methods, ports, `scinvoke` /
  `transfer` shapes, atomic units): https://docs.dero.io/Developers/rpcapi/
- DVM (BASIC `STORE`/`LOAD`/`EXISTS`, `transfer` + `sc_rpc` deposit
  pattern): https://docs.dero.io/Developers/dvm/
- DVM-BASIC reference: https://wiki.dero.io/wiki/index.php/DVM-BASIC
- Atlantis RPC API v2.0 PDF (wallet default port `20209`):
  https://forum.dero.io/uploads/default/original/1X/e42bf0e2611a01bd5fcbb88cc68c78e64f44bc86.pdf
- XSWD / bridge clients: `dero-xswd-api`, `go-dero-xswd-api`
  (dero-community), `dero-rpc-bridge`
  (https://github.com/g45t345rt/dero-rpc-bridge)
