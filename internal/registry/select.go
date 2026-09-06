// Node selection: latency / load / price / uptime / local history.
//
// Select scores active nodes and returns the best one. Weights are
// fixed and documented so operators can reason about routing; they are
// not tuned per-packet or per-byte. Local history (past session
// outcomes recorded by the client) biases toward nodes that worked.
//
// Scoring (lower is better):
//
//	score = wPrice*priceNorm + wLatency*latNorm + wLoad*load
//	      + wUptime*(1-uptime) - wHistory*history
//
// where price/latency are min-max normalized over the candidate set,
// load is the reported 0..1 utilization, uptime is 0..1, and history
// is the History score 0..1 (1 = flawless past sessions).
package registry

import (
	"errors"
	"sort"
)

const (
	wPrice   = 0.30
	wLatency = 0.30
	wLoad    = 0.15
	wUptime  = 0.15
	wHistory = 0.10
)

// NodeStats carries the dynamic signals for one node at select time.
// DERO NEVER carries these: they are measured locally, never on-chain.
type NodeStats struct {
	// LatencyMs is the measured round-trip (lower wins).
	LatencyMs float64
	// Load is 0..1 reported utilization (lower wins).
	Load float64
	// Uptime is 0..1 long-term availability (higher wins).
	Uptime float64
}

// History scores past local sessions per node_id, 0..1.
// Implementations clip to range; nil History means "no opinion".
type History interface {
	Score(nodeID string) float64
}

// Criteria filters and ranks candidates.
type Criteria struct {
	// Region, when non-empty, restricts to that region code.
	Region string
	// MaxPricePerHour, when > 0, excludes pricier nodes.
	MaxPricePerHour float64
	// Stats maps node_id to live signals. Missing entries score
	// neutrally (mid latency, mid load, full uptime unknown -> 0.5).
	Stats map[string]NodeStats
	// History biases toward locally reliable nodes. Nil = no bias.
	History History
}

// ErrNoCandidates means no active node passed the filters.
var ErrNoCandidates = errors.New("registry: no suitable node")

func clip01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// Select returns the best active node for c. Ties break on lower price,
// then lexicographically smaller node_id (deterministic).
func (s *Store) Select(c Criteria) (Node, error) {
	cands := s.Active()
	filtered := cands[:0:0]
	for _, n := range cands {
		if c.Region != "" && n.Region != c.Region {
			continue
		}
		if c.MaxPricePerHour > 0 && n.PricePerHourDERO > c.MaxPricePerHour {
			continue
		}
		filtered = append(filtered, n)
	}
	if len(filtered) == 0 {
		return Node{}, ErrNoCandidates
	}
	// Min-max normalize price and latency over the candidate set.
	minP, maxP := filtered[0].PricePerHourDERO, filtered[0].PricePerHourDERO
	minL, maxL := 0.0, 0.0
	first := true
	latOf := func(n Node) float64 {
		if st, ok := c.Stats[n.NodeID]; ok && st.LatencyMs > 0 {
			return st.LatencyMs
		}
		return 0 // unknown: scored neutrally below
	}
	for _, n := range filtered {
		if n.PricePerHourDERO < minP {
			minP = n.PricePerHourDERO
		}
		if n.PricePerHourDERO > maxP {
			maxP = n.PricePerHourDERO
		}
		l := latOf(n)
		if first {
			minL, maxL, first = l, l, false
		} else {
			if l < minL {
				minL = l
			}
			if l > maxL {
				maxL = l
			}
		}
	}
	norm := func(v, lo, hi float64) float64 {
		if hi <= lo {
			return 0
		}
		return (v - lo) / (hi - lo)
	}
	type scored struct {
		n     Node
		score float64
	}
	out := make([]scored, 0, len(filtered))
	for _, n := range filtered {
		lat, load, up := 0.5, 0.5, 0.5 // neutral when unknown
		if s2, has := c.Stats[n.NodeID]; has {
			if s2.LatencyMs > 0 {
				lat = norm(s2.LatencyMs, minL, maxL)
			}
			if s2.Load >= 0 && s2.Load <= 1 {
				load = s2.Load
			}
			if s2.Uptime >= 0 && s2.Uptime <= 1 {
				up = s2.Uptime
			}
		} else {
			lat = norm(latOf(n), minL, maxL)
		}
		hist := 0.5
		if c.History != nil {
			hist = clip01(c.History.Score(n.NodeID))
		}
		score := wPrice*norm(n.PricePerHourDERO, minP, maxP) +
			wLatency*lat +
			wLoad*clip01(load) +
			wUptime*(1-clip01(up)) -
			wHistory*hist
		out = append(out, scored{n: n, score: score})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score < out[j].score
		}
		if out[i].n.PricePerHourDERO != out[j].n.PricePerHourDERO {
			return out[i].n.PricePerHourDERO < out[j].n.PricePerHourDERO
		}
		return out[i].n.NodeID < out[j].n.NodeID
	})
	return out[0].n, nil
}

// MapHistory is an in-memory History for tests and the local client.
type MapHistory map[string]float64

// Score implements History, clipping to 0..1, defaulting to 0.5.
func (m MapHistory) Score(nodeID string) float64 {
	if m == nil {
		return 0.5
	}
	v, ok := m[nodeID]
	if !ok {
		return 0.5
	}
	return clip01(v)
}
