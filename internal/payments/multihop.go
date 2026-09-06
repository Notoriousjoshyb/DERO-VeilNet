// Multi-hop single-approval billing.
//
// A circuit pays pro-rata per hop (hours * hop-rate), but the user
// approves ONCE for the whole path: MultiHopApproval embeds one
// ApprovalPayload covering the summed Total plus the per-hop breakdown.
// Settlement runs per hop through the standard Service flow (one
// aggregate, idempotent RecordSettlement call per hop node). There is no
// per-hop prompt, no auto-spend, and no change to payments.go — this file
// is additive only.
package payments

import (
	"context"
	"errors"
	"fmt"

	"github.com/dero-veilnet/veilnet/internal/multihop"
)

// MultiHopApproval is the single dialog model for a whole circuit:
// one Total the user authorises, with per-hop pro-rata shares attached
// so the UI can show exactly where the money goes.
type MultiHopApproval struct {
	ApprovalPayload
	HopQuotes      []multihop.HopQuote `json:"hop_quotes"`
	Total          float64             `json:"total_dero"`
	SingleApproval bool                `json:"single_approval"`
}

// ApprovalForRoute builds the single-approval dialog for hours of session
// time on route r. depositDERO caps the approval total; operatorAddr and
// network label the dialog; balanceDERO is the wallet balance shown for
// context. Pure constructor: no spend, no chain reads, no token minting.
func ApprovalForRoute(r *multihop.Route, hours, depositDERO float64, operatorAddr, network string, balanceDERO float64) (MultiHopApproval, error) {
	if r == nil || len(r.Hops) == 0 {
		return MultiHopApproval{}, errors.New("payments: cannot approve an empty route")
	}
	q, err := multihop.QuoteRoute(r, hours)
	if err != nil {
		return MultiHopApproval{}, err
	}
	if depositDERO < q.Total {
		return MultiHopApproval{}, fmt.Errorf("payments: deposit %.4f DERO below circuit cost %.4f DERO for %.2fh (raise the deposit or shorten the session)", depositDERO, q.Total, hours)
	}
	path := ""
	for i, h := range r.Hops {
		if i > 0 {
			path += "->"
		}
		path += h.NodeID
	}
	return MultiHopApproval{
		ApprovalPayload: ApprovalPayload{
			NodeID:        path,
			Endpoint:      r.Exit().Endpoint,
			OperatorAddr:  operatorAddr,
			DepositDERO:   depositDERO,
			PricePerHour:  r.TotalPricePerHour(),
			EstHours:      hours,
			Network:       network,
			WalletBalance: balanceDERO,
		},
		HopQuotes:      q.HopQuotes,
		Total:          q.Total,
		SingleApproval: true,
	}, nil
}

// SettleRoute settles each circuit hop through the standard flow: one
// aggregate RecordSettlement call per hop node (idempotent batch dedup
// included), never per-packet or per-receipt transactions. Receipts land
// per hop via RecordReceipt first, so the receipt rules (non-empty id,
// non-negative amount, overspend rejection) apply hop by hop. Returns one
// Settlement per hop that had unsettled receipts, in path order.
func SettleRoute(ctx context.Context, s *Service, r *multihop.Route) ([]Settlement, error) {
	if s == nil {
		return nil, errors.New("payments: settlement needs a service")
	}
	if r == nil || len(r.Hops) == 0 {
		return nil, errors.New("payments: cannot settle an empty route")
	}
	out := make([]Settlement, 0, len(r.Hops))
	for _, h := range r.Hops {
		st, err := s.RecordSettlement(ctx, h.NodeID)
		if err != nil {
			return out, err
		}
		if len(st.ReceiptIDs) > 0 {
			out = append(out, st)
		}
	}
	return out, nil
}
