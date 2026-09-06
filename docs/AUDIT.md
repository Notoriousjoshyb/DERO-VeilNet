# AUDIT — tokens, payments, settlement contract, session (v1.1 hardening)

Owner: HardenAgent. Scope: `internal/tokens`, `internal/payments`,
`contracts/veilnet.bas`, `internal/session` — line-by-line review of the
token lifecycle, receipt/settlement accounting, on-chain attestation,
and node-side session enforcement. Fixes landed in the working tree
(see Status column); every fixed finding has a regression test in
`tests/audit/audit_test.go` that fails on the pre-fix behavior.

Method: read every function in the four areas, traced attacker-controlled
inputs (presented token strings, node-signed receipt fields, contract
call args, dev-validator inputs), checked each arithmetic conversion and
comparison for timing/overflow/replay flaws. `internal/dero` amount
helpers (`ToAtomic`/`FromAtomic`, 100000 atomic = 1 DERO) were read but
are out of scope (read-only this wave).

## Findings

| ID | Area | Finding | Severity | Status | Proof |
|----|------|---------|----------|--------|-------|
| T1 | tokens | `Validate` compared secrets with raw `ConstantTimeCompare`, which short-circuits on length mismatch — secret-length oracle | Medium | **Fixed** (`tokens.go`: SHA-256 both sides before compare + dummy compare on unknown ids) | `TestAuditTokenForgeryRejected` |
| T2 | tokens | `Sweep` deleted expired records immediately, so replays reported `ErrInvalid` (forged) instead of `ErrExpired` | Low | **Fixed** (`tokens.go`: 24h `expiredGrace`, revocations kept forever) | `TestAuditTokenExpiryAndSweepGrace` |
| T3 | tokens | "Single-use" doc claim vs pure `Validate` (no consumption on verify) | Low | **Mitigated** — single-active enforced + revoke-on-expiry in session layer (`SweepOnce` tombstones expired ids) | `TestAuditSessionRevocationBlocksReauthorize` |
| S1 | session | `StaticValidator.Validate` early-return scan leaked membership/position via timing | Low | **Fixed** (full scan, no early return) | behavior preserved by session tests |
| S2 | session | `Manager.Authorize` revocation check was a direct map lookup (timing oracle) | Low | **Fixed** (constant-time scan, matches `IsRevoked`) | `TestAuditSessionRevocationBlocksReauthorize` |
| S3 | session | `IsRevoked` early-`return true` inside scan loop | Low | **Fixed** (accumulate, no early return) | same as S2 |
| S4 | session | Dev validator truncated IDs to 8 chars — distinct tokens collide (session confusion/DoS) | Medium | **Fixed** (`devID` = SHA-256 hex of full string) | `TestAuditDevValidatorExpirySuffixAndIDs` |
| S5 | session | Dev validator ignored the documented `payload\|expiry` suffix — expired dev tokens accepted | Medium | **Fixed** (suffix honored: past → `ErrExpired`, malformed → `ErrInvalid`) | same test |
| P1 | payments | `RecordReceipt` accepted negative `Amount` (spend-accounting corruption; see P3) | High | **Fixed** (reject negative + empty id) | `TestAuditReceiptTamperRejected` |
| P2 | payments | No overspend check: a malicious node could inflate `Amount` past the funded deposit | High | **Fixed** (pending-aware guard vs `RemainingAtomic`) | `TestAuditReceiptOverspendRejected` |
| P3 | payments | Settlement `total += Amount` unchecked int64; negative total wrapped via `uint64(total)` into a huge on-chain value | High | **Fixed** (checked add, negative reject before conversion) | `TestAuditSettlementCheckedAggregation` |
| P4 | payments | `SpentAtomic += Amount` attribution unchecked (wrap past deposit) | Medium | **Fixed** (saturating add, capped at deposit) | same test (total == 700) |
| P5 | payments | Nanotime settlement IDs: a wallet-submit retry after timeout re-settles the same batch (double-count) | Medium | **Fixed** (deterministic `batchIDFor` = `stl-`+hex(sha256(sorted ids))) + contract Idem entrypoint (C5) | determinism assertions in same test |
| C1 | contract | `Initialize` re-callable by anyone — overwrites `owner` (takeover) | High | **Fixed** (`EXISTS("owner")` guard → RETURN 1) | code + redeploy note below |
| C2 | contract | `DepositBond` accepted `amount == 0` and wrapped on Uint64 overflow | Medium | **Fixed** (zero + overflow guards) | code |
| C3 | contract | `WithdrawBond` accepted `amount == 0` as success | Low | **Fixed** (zero guard) | code |
| C4 | contract | `RecordSettlement` had no replay protection — resubmission double-counts `_settled` | High | **Fixed**: new `RecordSettlementIdem(nodeID,total,count,batchID)` with `lastbatch` dedup (repeat → RETURN 0, no count); legacy path hardened (count==0 + overflow guards) and retained for deployed clients | payments calls Idem; determinism test |
| C5 | contract | `DepositBond` trusts the `amount` param — BASIC cannot read the attached transfer value | Medium | **Acknowledged**: not fixable on-chain; existing comment requires observers to verify attached tx value equals the bonded delta. No change (would need indexer-side enforcement) | — |
| C6 | contract | `WithdrawBond` has no unbonding delay — instant withdrawal before fraud review | Low | **Acknowledged**: operator-policy recommendation (maintain off-chain bond floor, monitor `GetBond`); timelock needs block-height access not assumed here | — |

## Explicitly clean (with evidence)

- **Mgmt bearer compare** (`nodes/store.go CheckBearer`): constant-time already; unchanged.
- **Session expiry tombstones** (`session SweepOnce` adds expired ids to `revoked`): replay-after-expiry rejected even before T2's grace window matters.
- **Receipt signature coverage** (`payments.receiptBody` binds id/session/node/token/rx/tx/minutes/amount): field tampering breaks `VerifyReceipt` — proven by `TestAuditReceiptTamperRejected`.
- **Duplicate receipts**: rejected by id (`TestAuditReceiptTamperRejected` replay leg).
- **Approval-before-spend** (`payments.Authorize`: approver verdict precedes `BuildTransfer`): correct order by inspection; `NeverApprover` default denies.
- **Complaint-log privacy** (`nodes/complaints.jsonl`): reporter/timestamp/reason/action only — proven by `TestAuditComplaintLogPrivacy` (fails on traffic-content keys).
- **Rate-limit fail-open**: empty buckets start full; nil guard disables enforcement (dev default unchanged).

## Notes for operators / deployers

- The `.bas` changes require a contract redeploy (or fresh deploy — pre-mainnet): new deployments should point clients at `RecordSettlementIdem`; the legacy entrypoint stays for compatibility.
- `RecordSettlementIdem` batch IDs are only replay-safe if deterministic per receipt set — `payments.batchIDFor` is the canonical derivation; third-party settlers MUST use the same scheme.
- Severity reflects the audit tree in isolation (single-hop, dev-stage); mainnet deployment needs a second pass with real wallet/chain fixtures.
