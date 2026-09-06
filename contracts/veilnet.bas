' VeilNet registry + settlement contract (DERO BASIC / DVM).
'
' Deploy once by the VeilNet operator; SCID is distributed with the
' client and node releases. DERO NEVER carries user traffic: this
' contract stores node advertisements, operator bonds, and periodic
' aggregate settlements only. There is deliberately NO per-packet,
' per-byte, or per-session transaction: clients pay prepaid off-chain
' quota and nodes settle signed receipt batches via RecordSettlement.
'
' Storage layout (all keys are strings):
'   "owner"                 installer address (SIGNER at Initialize)
'   "node_"+ID+"_owner"     registering signer (operator)
'   "node_"+ID+"_meta"      last advertisement blob (client-set string)
'   "node_"+ID+"_price"     price per hour, atomic units (Uint64)
'   "node_"+ID+"_bond"      locked bond, atomic units (Uint64)
'   "node_"+ID+"_status"    1 = active, 0 = disabled
'   "node_"+ID+"_settled"   lifetime settled total, atomic units
'
' Amounts arrive as Uint64 atomic units (100000 = 1 DERO). Bond top-ups
' use `transfer` with sc_rpc so value attaches to DepositBond; all
' other entrypoints are plain `scinvoke` calls.
'
' Every state-changing function returns 0 on success, 1 on failure.
' LOAD on a missing key panics, so EXISTS guards every read.

Function Initialize() Uint64
10 IF EXISTS("owner") == 1 THEN GOTO 50
20 STORE("owner", SIGNER())
30 RETURN 0
50 RETURN 1
End Function
' RegisterNode records a new node. Fails if the id is taken.
Function RegisterNode(nodeID String, meta String, price Uint64) Uint64
10 IF EXISTS("node_"+nodeID+"_owner") == 1 THEN GOTO 60
20 STORE("node_"+nodeID+"_owner", SIGNER())
30 STORE("node_"+nodeID+"_meta", meta)
40 STORE("node_"+nodeID+"_price", price)
50 STORE("node_"+nodeID+"_status", 1)
55 IF EXISTS("node_"+nodeID+"_bond") == 0 THEN STORE("node_"+nodeID+"_bond", 0)
56 IF EXISTS("node_"+nodeID+"_settled") == 0 THEN STORE("node_"+nodeID+"_settled", 0)
57 RETURN 0
60 RETURN 1
End Function

' UpdateNode replaces meta/price. Only the registering operator may call.
Function UpdateNode(nodeID String, meta String, price Uint64) Uint64
10 IF EXISTS("node_"+nodeID+"_owner") == 0 THEN GOTO 60
20 IF LOAD("node_"+nodeID+"_owner") != SIGNER() THEN GOTO 60
30 STORE("node_"+nodeID+"_meta", meta)
40 STORE("node_"+nodeID+"_price", price)
50 RETURN 0
60 RETURN 1
End Function

' DisableNode marks the node inactive. Operator or contract owner.
Function DisableNode(nodeID String) Uint64
10 IF EXISTS("node_"+nodeID+"_owner") == 0 THEN GOTO 60
20 IF LOAD("node_"+nodeID+"_owner") != SIGNER() THEN GOTO 30
25 GOTO 40
30 IF LOAD("owner") != SIGNER() THEN GOTO 60
40 STORE("node_"+nodeID+"_status", 0)
50 RETURN 0
60 RETURN 1
End Function

' SetPrice adjusts the hourly rate (atomic units). Operator only.
Function SetPrice(nodeID String, price Uint64) Uint64
10 IF EXISTS("node_"+nodeID+"_owner") == 0 THEN GOTO 60
20 IF LOAD("node_"+nodeID+"_owner") != SIGNER() THEN GOTO 60
30 STORE("node_"+nodeID+"_price", price)
40 RETURN 0
60 RETURN 1
End Function
' DepositBond attests a bond top-up of `amount` atomic units.
' Invoke with `transfer` + sc_rpc so matching DERO value attaches to
' the call; observers verify the attached tx value equals the bonded
' delta. The contract tracks the lock, the chain tracks the value.
Function DepositBond(nodeID String, amount Uint64) Uint64
10 IF EXISTS("node_"+nodeID+"_owner") == 0 THEN GOTO 70
20 IF LOAD("node_"+nodeID+"_owner") != SIGNER() THEN GOTO 70
25 IF amount == 0 THEN GOTO 70
30 IF EXISTS("node_"+nodeID+"_bond") == 0 THEN STORE("node_"+nodeID+"_bond", 0)
35 IF LOAD("node_"+nodeID+"_bond") + amount < LOAD("node_"+nodeID+"_bond") THEN GOTO 70
40 STORE("node_"+nodeID+"_bond", LOAD("node_"+nodeID+"_bond") + amount)
50 RETURN 0
70 RETURN 1
End Function

' WithdrawBond releases part of the bond back to the operator.
' Real payout is handled by the operator wallet flow; the contract
' only attests the reduced lock so clients can verify cover.
Function WithdrawBond(nodeID String, amount Uint64) Uint64
10 IF EXISTS("node_"+nodeID+"_bond") == 0 THEN GOTO 60
20 IF LOAD("node_"+nodeID+"_owner") != SIGNER() THEN GOTO 60
30 IF LOAD("node_"+nodeID+"_bond") < amount THEN GOTO 60
35 IF amount == 0 THEN GOTO 60
40 STORE("node_"+nodeID+"_bond", LOAD("node_"+nodeID+"_bond") - amount)
50 RETURN 0
60 RETURN 1
End Function

' RecordSettlement attests an aggregate receipt batch for a node.
' Operator or contract owner; total is the summed atomic batch value,
' count is the number of receipts aggregated (auditing aid).
Function RecordSettlement(nodeID String, total Uint64, count Uint64) Uint64
10 IF EXISTS("node_"+nodeID+"_owner") == 0 THEN GOTO 60
20 IF LOAD("node_"+nodeID+"_owner") != SIGNER() THEN GOTO 30
25 GOTO 40
30 IF LOAD("owner") != SIGNER() THEN GOTO 60
35 IF EXISTS("node_"+nodeID+"_settled") == 0 THEN STORE("node_"+nodeID+"_settled", 0)
40 IF count == 0 THEN GOTO 60
45 IF LOAD("node_"+nodeID+"_settled") + total < LOAD("node_"+nodeID+"_settled") THEN GOTO 60
50 STORE("node_"+nodeID+"_settled", LOAD("node_"+nodeID+"_settled") + total)
55 STORE("node_"+nodeID+"_lastcount", count)
56 RETURN 0
60 RETURN 1
End Function

' RecordSettlementIdem is the replay-safe variant of RecordSettlement.
' batchID MUST be deterministic per receipt set (client: hex-encoded
' SHA-256 over the sorted receipt IDs, see internal/payments). A repeat
' submission of the same batchID is acknowledged (RETURN 0) WITHOUT
' double-counting, so wallet-submit retries after a timeout are safe.
' Prefer this over RecordSettlement for all new integrations; the
' legacy entrypoint is retained for deployed clients.
Function RecordSettlementIdem(nodeID String, total Uint64, count Uint64, batchID String) Uint64
10 IF EXISTS("node_"+nodeID+"_owner") == 0 THEN GOTO 90
20 IF LOAD("node_"+nodeID+"_owner") != SIGNER() THEN GOTO 30
25 GOTO 40
30 IF LOAD("owner") != SIGNER() THEN GOTO 90
40 IF count == 0 THEN GOTO 90
45 IF batchID == "" THEN GOTO 90
50 IF EXISTS("node_"+nodeID+"_lastbatch") == 0 THEN GOTO 70
55 IF LOAD("node_"+nodeID+"_lastbatch") != batchID THEN GOTO 70
56 RETURN 0
70 IF EXISTS("node_"+nodeID+"_settled") == 0 THEN STORE("node_"+nodeID+"_settled", 0)
72 IF LOAD("node_"+nodeID+"_settled") + total < LOAD("node_"+nodeID+"_settled") THEN GOTO 90
74 STORE("node_"+nodeID+"_settled", LOAD("node_"+nodeID+"_settled") + total)
76 STORE("node_"+nodeID+"_lastcount", count)
78 STORE("node_"+nodeID+"_lastbatch", batchID)
80 RETURN 0
90 RETURN 1
End Function
60 RETURN 1
End Function

' GetPrice returns the hourly rate (atomic units), 0 if unknown.
Function GetPrice(nodeID String) Uint64
10 IF EXISTS("node_"+nodeID+"_price") == 0 THEN GOTO 30
20 RETURN LOAD("node_"+nodeID+"_price")
30 RETURN 0
End Function

' GetStatus returns 1 active, 0 disabled/unknown.
Function GetStatus(nodeID String) Uint64
10 IF EXISTS("node_"+nodeID+"_status") == 0 THEN GOTO 30
20 RETURN LOAD("node_"+nodeID+"_status")
30 RETURN 0
End Function

' GetBond returns the locked bond (atomic units), 0 if unknown.
Function GetBond(nodeID String) Uint64
10 IF EXISTS("node_"+nodeID+"_bond") == 0 THEN GOTO 30
20 RETURN LOAD("node_"+nodeID+"_bond")
30 RETURN 0
End Function
