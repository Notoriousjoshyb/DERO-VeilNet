package ref

import (
	"errors"
	"sort"
	"strings"
)

// NodeMeta mirrors the Contract node metadata.
type NodeMeta struct {
	NodeID          string
	WGPubkey        string
	Region          string
	Country         string
	City            string
	Endpoint        string
	PricePerHour    float64
	CapacityMax     int
	ClientsActive   int
	ProtocolVersion int
	BondDero        float64
	Status          string // "online", "draining", "offline"
	Version         string
}

// CurrentProtocol is the client protocol version selection enforces.
const CurrentProtocol = 1

// Validatesoa checks registry-entry integrity: rejects spoofed entries with
// empty identity, empty WireGuard key, negative pricing, or zero capacity.
func ValidateNode(n NodeMeta) error {
	if strings.TrimSpace(n.NodeID) == "" {
		return errors.New("ref: node_id required")
	}
	if strings.TrimSpace(n.WGPubkey) == "" {
		return errors.New("ref: wg_pubkey required (spoof reject)")
	}
	if len(strings.Fields(n.WGPubkey)) != 1 || len(n.WGPubkey) < 40 {
		return errors.New("ref: wg_pubkey malformed (spoof reject)")
	}
	if strings.TrimSpace(n.Endpoint) == "" {
		return errors.New("ref: endpoint required")
	}
	if n.PricePerHour < 0 {
		return errors.New("ref: negative price rejected")
	}
	if n.CapacityMax <= 0 {
		return errors.New("ref: capacity must be positive")
	}
	if n.ProtocolVersion <= 0 {
		return errors.New("ref: protocol_version required")
	}
	switch n.Status {
	case "online", "draining", "offline":
	default:
		return errors.New("ref: unknown status")
	}
	return nil
}

// Eligible reports whether n may serve a new client.
func Eligible(n NodeMeta) bool {
	if ValidateNode(n) != nil {
		return false
	}
	if n.Status != "online" {
		return false
	}
	if n.ProtocolVersion != CurrentProtocol {
		return false
	}
	if n.ClientsActive >= n.CapacityMax {
		return false
	}
	return true
}

// Signal carries one selection observation per Contract criteria:
// latency, load, price, uptime, local history.
type Signal struct {
	LatencyMS   float64
	UptimePct   float64 // 0..100
	HistoryGood int     // successful local sessions
	HistoryBad  int     // failed local sessions
}

// Score ranks eligible nodes: lower is better. Latency dominates, then load
// ratio, then price, with uptime discount and local-history adjustment.
// Score returns false for ineligible nodes.
func Score(n NodeMeta, s Signal) (float64, bool) {
	if !Eligible(n) {
		return 0, false
	}
	load := float64(n.ClientsActive) / float64(n.CapacityMax)
	score := s.LatencyMS*1.0 + load*200.0 + n.PricePerHour*50.0
	score -= s.UptimePct * 0.5
	score -= float64(s.HistoryGood) * 5.0
	score += float64(s.HistoryBad) * 25.0
	return score, true
}

// Select returns eligible nodes ordered best-first. Empty when none qualify.
func Select(nodes []NodeMeta, signals map[string]Signal) []NodeMeta {
	type ranked struct {
		n NodeMeta
		s float64
	}
	var rs []ranked
	for _, n := range nodes {
		sc, ok := Score(n, signals[n.NodeID])
		if !ok {
			continue
		}
		rs = append(rs, ranked{n, sc})
	}
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].s == rs[j].s {
			return rs[i].n.NodeID < rs[j].n.NodeID
		}
		return rs[i].s < rs[j].s
	})
	out := make([]NodeMeta, len(rs))
	for i, r := range rs {
		out[i] = r.n
	}
	return out
}
