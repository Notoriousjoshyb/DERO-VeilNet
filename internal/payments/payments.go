// Package payments implements prepaid session credit funded by DERO
// with explicit user approval.
//
// Flow: USER -> PREPAID -> RECEIPTS -> SETTLEMENT (see docs/PAYMENTS.md).
//
//   1. Authorize: the UI shows an ApprovalPayload {node, operator
//      address, deposit, estimated hours, network} and the user returns
//      AUTHORISE or REJECT. REJECT aborts before any chain read.
//   2. Funding is checked against the wallet balance; the deposit buys
//      quota hours = deposit / price_per_hour. No per-packet
//      transactions: the chain sees at most one funding transfer and
//      periodic aggregate settlements.
//   3. The service mints a bearer token (internal/tokens) scoped to the
//      node. The node validates it through the session adapter; wallet
//      seeds/keys are NEVER sent to the node.
//   4. Usage accumulates as node-signed receipts (ed25519). Settle
//      aggregates unreceipted... unSETtled receipts into one
//      RecordSettlement contract call via the wallet.
//
// Demo mode: NewDemoService wires DevMock wallet + auto approver; the
// wallet is optional there (nil wallet = simulated funding, zero spend,
// clearly badged by the caller).
package payments

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dero-veilnet/veilnet/internal/dero"
	"github.com/dero-veilnet/veilnet/internal/events"
	"github.com/dero-veilnet/veilnet/internal/registry"
	"github.com/dero-veilnet/veilnet/internal/tokens"
)

// Decision is the user verdict on an ApprovalPayload.
type Decision string

const (
	// DecisionAuthorise proceeds with funding + token mint.
	DecisionAuthorise Decision = "AUTHORISE"
	// DecisionReject aborts before any spend or chain read.
	DecisionReject Decision = "REJECT"
)

// ApprovalPayload is the dialog model. The UI MUST render every field
// and return the user's explicit verdict; there is no default-allow.
type ApprovalPayload struct {
	NodeID        string  `json:"node_id"`
	Endpoint      string  `json:"endpoint"`
	OperatorAddr  string  `json:"operator_addr"`
	DepositDERO   float64 `json:"deposit_dero"`
	PricePerHour  float64 `json:"price_per_hour_dero"`
	EstHours      float64 `json:"est_hours"`
	Network       string  `json:"network"`
	WalletBalance float64 `json:"wallet_balance_dero"`
}

// Estimate returns quota hours = deposit / price (Inf on free nodes).
func (a ApprovalPayload) Estimate() float64 {
	if a.PricePerHour <= 0 {
		return -1 // free / unspecified price: unbounded by payment
	}
	return a.DepositDERO / a.PricePerHour
}

// Approver renders ApprovalPayload and returns the user verdict.
type Approver interface {
	RequestApproval(ctx context.Context, p ApprovalPayload) (Decision, error)
}

// AutoApprover authorises everything. Tests and `--demo` only.
type AutoApprover struct{}

// RequestApproval implements Approver.
func (AutoApprover) RequestApproval(ctx context.Context, p ApprovalPayload) (Decision, error) {
	return DecisionAuthorise, nil
}

// NeverApprover rejects everything. It is the safe default: no wallet
// movement until the real UI wires an approver.
type NeverApprover struct{}

// RequestApproval implements Approver.
func (NeverApprover) RequestApproval(ctx context.Context, p ApprovalPayload) (Decision, error) {
	return DecisionReject, nil
}

// ErrRejected means the user refused the spend.
var ErrRejected = errors.New("payments: user rejected approval")

// Prepaid is one funded session credit.
type Prepaid struct {
	SessionID      string
	NodeID         string
	DepositAtomic  int64
	SpentAtomic    int64
	PricePerHour   float64
	FundedAt       time.Time
	FundingTXID    string
}

// NewPrepaid funds quota from depositDERO at pricePerHour.
// Example: 2.0 DERO at 0.5/hr -> 4 quota hours.
func NewPrepaid(sessionID, nodeID string, depositDERO, pricePerHour float64) (*Prepaid, error) {
	if sessionID == "" || nodeID == "" {
		return nil, errors.New("payments: session and node required")
	}
	dep := dero.ToAtomic(depositDERO)
	if dep <= 0 {
		return nil, errors.New("payments: deposit must be > 0")
	}
	if pricePerHour < 0 {
		return nil, errors.New("payments: negative price")
	}
	return &Prepaid{
		SessionID:     sessionID,
		NodeID:        nodeID,
		DepositAtomic: dep,
		PricePerHour:  pricePerHour,
		FundedAt:      time.Now(),
	}, nil
}

// QuotaHours is deposit/price; -1 means unbounded (free node).
func (p *Prepaid) QuotaHours() float64 {
	if p.PricePerHour <= 0 {
		return -1
	}
	return dero.FromAtomic(p.DepositAtomic) / p.PricePerHour
}

// RemainingAtomic is the unspent balance.
func (p *Prepaid) RemainingAtomic() int64 {
	return p.DepositAtomic - p.SpentAtomic
}

// Receipt is a node-signed usage record. Counters only: traffic
// content is never logged, only byte totals and duration.
type Receipt struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	NodeID    string `json:"node_id"`
	TokenID   string `json:"token_id"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	Minutes   uint64 `json:"minutes"`
	Amount    int64  `json:"amount_atomic"`
	Settled   bool   `json:"settled"`
	// NodePub is the 32-byte ed25519 node signing key; Sig signs the
	// canonical receipt body (all fields above).
	NodePub []byte `json:"node_pub"`
	Sig     []byte `json:"sig"`
}

func receiptBody(r Receipt) []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%s|%d|%d|%d|%d",
		r.ID, r.SessionID, r.NodeID, r.TokenID,
		r.RxBytes, r.TxBytes, r.Minutes, r.Amount))
}

// SignReceipt signs r with the node operator key.
func SignReceipt(r *Receipt, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("payments: bad node private key size")
	}
	pub := priv.Public().(ed25519.PublicKey)
	r.NodePub = []byte(pub)
	r.Sig = ed25519.Sign(priv, receiptBody(*r))
	return nil
}

// VerifyReceipt checks the node signature.
func VerifyReceipt(r Receipt) error {
	if len(r.NodePub) != ed25519.PublicKeySize {
		return errors.New("payments: bad node public key size")
	}
	if len(r.Sig) != ed25519.SignatureSize {
		return errors.New("payments: bad receipt signature size")
	}
	if !ed25519.Verify(ed25519.PublicKey(r.NodePub), receiptBody(r), r.Sig) {
		return errors.New("payments: receipt signature verification failed")
	}
	return nil
}

// Settlement aggregates receipts into one on-chain RecordSettlement
// call. There is deliberately no per-packet or per-receipt tx.
type Settlement struct {
	ID         string
	NodeID     string
	ReceiptIDs []string
	Total      int64
	TXID       string
	At         time.Time
}

// Service orchestrates authorize -> token -> receipts -> settlement.
// It is safe for concurrent use.
type Service struct {
	mu         sync.Mutex
	wallet     dero.WalletClient // nil in wallet-less demo
	issuer     *tokens.Issuer
	reg        *registry.Store
	approver   Approver
	network    dero.Network
	scid       string // veilnet registry/settlement contract
	prepaid    map[string]*Prepaid // sessionID -> credit
	receipts   map[string]Receipt  // receiptID -> receipt
	settled    []Settlement
	receiptSeq int
}

// Options tunes a Service.
type Options struct {
	// Wallet is the funding wallet; nil = wallet-less demo (funding
	// simulated, zero spend possible).
	Wallet dero.WalletClient
	// Issuer mints session tokens; nil creates one.
	Issuer *tokens.Issuer
	// Registry resolves node price/operator; nil skips lookup.
	Registry *registry.Store
	// Approver renders the approval dialog; nil denies all.
	Approver Approver
	// Network labels approval payloads and gates real submits.
	Network dero.Network
	// SCID is the veilnet contract for RecordSettlement; "" skips
	// chain submission and records settlements locally.
	SCID string
}

// NewService builds a Service with safe defaults.
func NewService(opts Options) *Service {
	if opts.Issuer == nil {
		opts.Issuer = tokens.NewIssuer()
	}
	if opts.Approver == nil {
		opts.Approver = NeverApprover{}
	}
	if opts.Network == "" {
		opts.Network = dero.NetworkDevMock
	}
	return &Service{
		wallet:   opts.Wallet,
		issuer:   opts.Issuer,
		reg:      opts.Registry,
		approver: opts.Approver,
		network:  opts.Network,
		scid:     opts.SCID,
		prepaid:  make(map[string]*Prepaid),
		receipts: make(map[string]Receipt),
	}
}

// NewDemoService builds a DevMock service: mock wallet funded with
// 100 DERO, auto approver, local issuer. Zero real-DERO spend.
func NewDemoService(reg *registry.Store) *Service {
	return NewService(Options{
		Wallet:   dero.NewMockWallet(),
		Issuer:   tokens.NewIssuer(),
		Registry: reg,
		Approver: AutoApprover{},
		Network:  dero.NetworkDevMock,
		SCID:     "devmock-veilnet-scid",
	})
}

// Grant is the successful Authorize outcome.
type Grant struct {
	Approval ApprovalPayload
	Credit   *Prepaid
	Token    tokens.Token
}

// Authorize runs the prepaid flow: resolve node price, ask the user,
// check funding, record prepaid credit, mint the session token.
// REJECT (or any approver error) aborts with ErrRejected before any
// spend. DERO outage aborts funding but never touches live tunnels.
func (s *Service) Authorize(ctx context.Context, nodeID, operatorAddr, sessionID string, depositDERO float64) (Grant, error) {
	price := 0.0
	endpoint := ""
	if s.reg != nil {
		n, ok := s.reg.Get(nodeID)
		if !ok {
			return Grant{}, fmt.Errorf("payments: unknown node %s", nodeID)
		}
		if n.Status != registry.StatusActive {
			return Grant{}, fmt.Errorf("payments: node %s not active", nodeID)
		}
		price = n.PricePerHourDERO
		endpoint = n.Endpoint
	}
	if operatorAddr == "" {
		return Grant{}, errors.New("payments: operator address required")
	}
	balanceDERO := -1.0 // unknown (wallet-less demo)
	if s.wallet != nil {
		bal, err := s.wallet.GetBalance(ctx)
		if err != nil {
			return Grant{}, dero.RequireFreshChain(err)
		}
		balanceDERO = dero.FromAtomic(int64(bal.UnlockedBalance))
		if int64(bal.UnlockedBalance) < dero.ToAtomic(depositDERO) {
			return Grant{}, fmt.Errorf("payments: insufficient unlocked balance %.4f < %.4f DERO",
				balanceDERO, depositDERO)
		}
	}
	payload := ApprovalPayload{
		NodeID:        nodeID,
		Endpoint:      endpoint,
		OperatorAddr:  operatorAddr,
		DepositDERO:   depositDERO,
		PricePerHour:  price,
		Network:       string(s.network),
		WalletBalance: balanceDERO,
	}
	payload.EstHours = payload.Estimate()
	events.Publish(events.PAYMENT_REQUESTED, payload)
	decision, err := s.approver.RequestApproval(ctx, payload)
	if err != nil {
		return Grant{}, fmt.Errorf("payments: approver: %w", err)
	}
	if decision != DecisionAuthorise {
		return Grant{}, ErrRejected
	}
	credit, err := NewPrepaid(sessionID, nodeID, depositDERO, price)
	if err != nil {
		return Grant{}, err
	}
	if s.wallet != nil {
		// Funding transfer: built here, submitted only post-approval
		// (which just happened above). Real networks only.
		u, err := s.wallet.BuildTransfer(dero.TransferRequest{
			Destination:  operatorAddr,
			AmountAtomic: uint64(credit.DepositAtomic),
		}, s.network)
		if err != nil {
			return Grant{}, err
		}
		txid, err := s.wallet.SubmitTransfer(ctx, u)
		if err != nil {
			return Grant{}, dero.RequireFreshChain(err)
		}
		credit.FundingTXID = txid
	} else {
		credit.FundingTXID = "demo-no-wallet"
	}
	ttl := 4 * time.Hour
	if payload.EstHours > 0 {
		ttl = time.Duration(payload.EstHours * float64(time.Hour))
	}
	tok, err := s.issuer.Mint(nodeID, sessionID, ttl, tokens.ScopeExit)
	if err != nil {
		return Grant{}, err
	}
	s.mu.Lock()
	s.prepaid[sessionID] = credit
	s.mu.Unlock()
	events.Publish(events.PAYMENT_CONFIRMED, payload)
	events.Publish(events.SESSION_AUTHORIZED, tok.ID)
	return Grant{Approval: payload, Credit: credit, Token: tok}, nil
}

// RecordReceipt verifies a node-signed receipt and stores it. It
// rejects negative amounts outright and receipts that would overspend
// the session's remaining prepaid credit (when the credit is known):
// a malicious node cannot inflate Amount past the funded deposit.
func (s *Service) RecordReceipt(r Receipt) error {
	if err := VerifyReceipt(r); err != nil {
		return err
	}
	if r.ID == "" {
		return errors.New("payments: receipt id required")
	}
	if r.Amount < 0 {
		return fmt.Errorf("payments: receipt %s negative amount %d", r.ID, r.Amount)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.receipts[r.ID]; dup {
		return fmt.Errorf("payments: duplicate receipt %s", r.ID)
	}
	if p, ok := s.prepaid[r.SessionID]; ok {
		var pending int64
		for _, e := range s.receipts {
			if e.SessionID == r.SessionID && !e.Settled {
				if pending > math.MaxInt64-e.Amount {
					return fmt.Errorf("payments: receipt %s pending total overflow", r.ID)
				}
				pending += e.Amount
			}
		}
		remaining := p.RemainingAtomic() - pending
		if r.Amount > remaining {
			return fmt.Errorf("payments: receipt %s amount %d exceeds remaining credit %d",
				r.ID, r.Amount, remaining)
		}
	}
	s.receipts[r.ID] = r
	return nil
}

// Unsettled returns stored, unsettled receipts for nodeID.
func (s *Service) Unsettled(nodeID string) []Receipt {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Receipt
	for _, r := range s.receipts {
		if r.NodeID == nodeID && !r.Settled {
			out = append(out, r)
		}
	}
	return out
}

// batchIDFor derives a deterministic batch ID: hex SHA-256 over the
// SORTED receipt IDs. The same receipt set always yields the same ID,
// so RecordSettlementIdem acknowledges retries without double-count.
func batchIDFor(ids []string) string {
	cp := append([]string(nil), ids...)
	sort.Strings(cp)
	sum := sha256.Sum256([]byte(strings.Join(cp, ",")))
	return "stl-" + hex.EncodeToString(sum[:])
}

// RecordSettlement aggregates unsettled receipts for nodeID into one
// settlement, submits RecordSettlementIdem (replay-safe, deterministic
// batchID) when a wallet+SCID exist, and marks the receipts settled.
// No per-packet tx: one call per batch.
func (s *Service) RecordSettlement(ctx context.Context, nodeID string) (Settlement, error) {
	s.mu.Lock()
	var batch []Receipt
	for _, r := range s.receipts {
		if r.NodeID == nodeID && !r.Settled {
			batch = append(batch, r)
		}
	}
	s.mu.Unlock()
	if len(batch) == 0 {
		return Settlement{}, fmt.Errorf("payments: nothing to settle for %s", nodeID)
	}
	// Checked aggregation: any negative amount (pre-guard receipt) or
	// int64 overflow aborts instead of wrapping. A negative total must
	// never reach uint64(total) below (wrap to a huge on-chain value).
	var total int64
	ids := make([]string, 0, len(batch))
	for _, r := range batch {
		if r.Amount < 0 {
			return Settlement{}, fmt.Errorf("payments: receipt %s negative amount %d", r.ID, r.Amount)
		}
		if total > math.MaxInt64-r.Amount {
			return Settlement{}, fmt.Errorf("payments: settlement total overflow for %s", nodeID)
		}
		total += r.Amount
		ids = append(ids, r.ID)
	}
	if total < 0 {
		return Settlement{}, fmt.Errorf("payments: negative settlement total for %s", nodeID)
	}
	batchID := batchIDFor(ids)
	st := Settlement{
		ID:         batchID,
		NodeID:     nodeID,
		ReceiptIDs: ids,
		Total:      total,
		At:         time.Now(),
	}
	if s.wallet != nil && s.scid != "" {
		u, err := s.wallet.BuildInvoke(s.scid, "RecordSettlementIdem", []dero.SCArg{
			{Name: "node_id", DataType: "S", Value: nodeID},
			{Name: "total", DataType: "U", Value: uint64(total)},
			{Name: "count", DataType: "U", Value: uint64(len(batch))},
			{Name: "batch_id", DataType: "S", Value: batchID},
		}, s.network)
		if err != nil {
			return Settlement{}, err
		}
		txid, err := s.wallet.SubmitInvoke(ctx, u)
		if err != nil {
			return Settlement{}, dero.RequireFreshChain(err)
		}
		st.TXID = txid
	} else {
		st.TXID = "demo-no-chain"
	}
	s.mu.Lock()
	for _, id := range ids {
		r := s.receipts[id]
		r.Settled = true
		s.receipts[id] = r
	}
	s.settled = append(s.settled, st)
	// Attribute spend to prepaid credit (best effort, per session).
	// Saturating addition: spend accounting must never wrap, and total
	// spend is capped at the funded deposit (overspend is rejected at
	// RecordReceipt; this is defense in depth).
	for _, r := range batch {
		if p, ok := s.prepaid[r.SessionID]; ok {
			if r.Amount >= 0 && p.SpentAtomic <= math.MaxInt64-r.Amount {
				p.SpentAtomic += r.Amount
			} else {
				p.SpentAtomic = math.MaxInt64
			}
			if p.SpentAtomic > p.DepositAtomic {
				p.SpentAtomic = p.DepositAtomic
			}
		}
	}
	s.mu.Unlock()
	return st, nil
}

// Issuer exposes the token issuer for node-side validators.
func (s *Service) Issuer() *tokens.Issuer { return s.issuer }
