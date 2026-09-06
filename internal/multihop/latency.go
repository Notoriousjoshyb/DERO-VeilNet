package multihop

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// alpha is the EWMA weight for each new RTT sample.
const alpha = 0.3

// Aggregator tracks per-node latency signals and scores candidates using
// the contract selection criteria: latency / load / price / uptime /
// local history. It stores only aggregate statistics — never traffic
// content, never per-destination data.
type Aggregator struct {
	mu      sync.Mutex
	ewma    map[string]float64 // node_id -> smoothed RTT ms
	samples map[string]int
	last    map[string]time.Time
	static  map[string]NodeInfo // last known static fields for scoring
}

// NewAggregator returns an empty latency aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{
		ewma:    make(map[string]float64),
		samples: make(map[string]int),
		last:    make(map[string]time.Time),
		static:  make(map[string]NodeInfo),
	}
}

// Observe records one RTT sample (milliseconds) for a node.
func (a *Aggregator) Observe(node NodeInfo, rttMs float64) {
	if rttMs < 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	id := node.NodeID
	if a.samples[id] == 0 {
		a.ewma[id] = rttMs
	} else {
		a.ewma[id] = alpha*rttMs + (1-alpha)*a.ewma[id]
	}
	a.samples[id]++
	a.last[id] = time.Now().UTC()
	node.Latency = a.ewma[id]
	a.static[id] = node
}

// Latency returns the smoothed RTT for a node, and whether any sample exists.
func (a *Aggregator) Latency(nodeID string) (float64, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, ok := a.ewma[nodeID]
	return v, ok
}

// Score ranks a node: lower is better. Weights: latency dominates, then
// load, price, with uptime/history as reliability bonuses. Nodes without
// samples sort worse than measured ones but are still selectable.
func Score(n NodeInfo, smoothedLatency float64, hasSample bool) float64 {
	lat := smoothedLatency
	if !hasSample {
		lat = 500 // unmeasured penalty, still selectable
	}
	s := lat +
		200*n.Load +
		10*n.PricePerHour +
		100*(1-n.Uptime) +
		50*(1-n.History)
	if s < 0 {
		return 0
	}
	return s
}

// Rank orders candidates best-first without mutating them.
func (a *Aggregator) Rank(cands []NodeInfo) []NodeInfo {
	a.mu.Lock()
	snap := make(map[string]float64, len(a.ewma))
	for k, v := range a.ewma {
		snap[k] = v
	}
	counts := make(map[string]int, len(a.samples))
	for k, v := range a.samples {
		counts[k] = v
	}
	a.mu.Unlock()
	out := append([]NodeInfo(nil), cands...)
	sort.SliceStable(out, func(i, j int) bool {
		li, oki := snap[out[i].NodeID]
		lj, okj := snap[out[j].NodeID]
		return Score(out[i], li, oki) < Score(out[j], lj, okj)
	})
	return out
}

// PickPair selects the best (entry, exit) distinct pair: the two lowest
// scoring nodes, cheapest-last so the exit (which carries session cost)
// prefers the lower price on ties. Returns false when fewer than 2
// usable nodes exist — the caller then falls back to BuildSingleHop.
func (a *Aggregator) PickPair(cands []NodeInfo) (entry, exit NodeInfo, ok bool) {
	ranked := a.Rank(cands)
	usable := ranked[:0:0]
	for _, n := range ranked {
		if n.Validate() == nil {
			usable = append(usable, n)
		}
	}
	if len(usable) < 2 {
		return NodeInfo{}, NodeInfo{}, false
	}
	return usable[0], usable[1], true
}

// FilterByBudget drops nodes whose measured latency exceeds budgetMs.
// Unmeasured nodes (Latency == 0) pass: absence of signal never blocks.
// budgetMs <= 0 disables the filter.
func FilterByBudget(cands []NodeInfo, budgetMs float64) []NodeInfo {
	if budgetMs <= 0 {
		return cands
	}
	out := make([]NodeInfo, 0, len(cands))
	for _, n := range cands {
		if n.Latency > 0 && n.Latency > budgetMs {
			continue
		}
		out = append(out, n)
	}
	return out
}

// SelectRoute picks an ordered entry -> ... -> exit path of up to maxHops
// nodes under the tradeoff knob:
//
//	fast     — lowest smoothed latency first (tight budget enforced);
//	balanced — best blended score (latency/load/price/uptime/history);
//	safe     — distinct countries preferred, slower hops tolerated.
//
// Every pick is validated and pairwise separation-checked (distinct nodes,
// distinct endpoint hosts, distinct operator keys), so the returned slice
// always passes BuildRoute. Returns the longest feasible path when the
// pool is thin (down to 1 hop); error only when no valid node exists.
func (a *Aggregator) SelectRoute(cands []NodeInfo, maxHops int, tradeoff Tradeoff) ([]NodeInfo, error) {
	if maxHops <= 0 {
		maxHops = 3
	}
	if maxHops > 3 {
		maxHops = 3
	}
	valid := make([]NodeInfo, 0, len(cands))
	for _, n := range cands {
		if n.Validate() == nil {
			valid = append(valid, n)
		}
	}
	if len(valid) == 0 {
		return nil, errors.New("multihop: no valid nodes to build a route (check node endpoints and keys)")
	}
	var budget float64
	switch tradeoff {
	case TradeoffFast:
		budget = FastLatencyBudgetMs
	case TradeoffSafe:
		budget = SafeLatencyBudgetMs
	}
	if filtered := FilterByBudget(valid, budget); len(filtered) > 0 {
		valid = filtered
	}
	// Fast ranks by measured latency alone; other modes use the blended
	// score so price/load/reliability still count.
	ranked := append([]NodeInfo(nil), valid...)
	if tradeoff == TradeoffFast {
		a.mu.Lock()
		snap := make(map[string]float64, len(a.ewma))
		for k, v := range a.ewma {
			snap[k] = v
		}
		a.mu.Unlock()
		sort.SliceStable(ranked, func(i, j int) bool {
			li := ranked[i].Latency
			if v, ok := snap[ranked[i].NodeID]; ok {
				li = v
			} else if li <= 0 {
				li = 500
			}
			lj := ranked[j].Latency
			if v, ok := snap[ranked[j].NodeID]; ok {
				lj = v
			} else if lj <= 0 {
				lj = 500
			}
			return li < lj
		})
	} else {
		ranked = a.Rank(valid)
	}
	// Greedy path: take the best-ranked node that keeps separation.
	// Safe mode additionally prefers a new country per hop.
	path := make([]NodeInfo, 0, maxHops)
	usedCountries := map[string]bool{}
	for pass := 0; pass < 2 && len(path) < maxHops; pass++ {
		for _, n := range ranked {
			if len(path) >= maxHops {
				break
			}
			if containsNode(path, n.NodeID) {
				continue
			}
			c := strings.ToUpper(strings.TrimSpace(n.Country))
			if tradeoff == TradeoffSafe && pass == 0 && c != "" && usedCountries[c] {
				continue
			}
			if err := checkDistinct(append(append([]NodeInfo(nil), path...), n)); err != nil {
				continue
			}
			path = append(path, n)
			if c != "" {
				usedCountries[c] = true
			}
		}
	}
	if len(path) == 0 {
		return nil, errors.New("multihop: pool cannot form a separated path (nodes share boxes or keys)")
	}
	return path, nil
}

func containsNode(path []NodeInfo, id string) bool {
	for _, n := range path {
		if n.NodeID == id {
			return true
		}
	}
	return false
}
