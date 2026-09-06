// Canonical 1-3 hop route construction and verification.
//
// Route is the canonical circuit shape: an ordered entry -> ... -> exit
// path with per-hop public dial data. It replaces the ad-hoc 2-hop-only
// handling with a uniform builder that enforces:
//
//   - 1-3 hops, never 0, never more than 3;
//   - distinct node IDs (loop rejection);
//   - distinct endpoint hosts (same-box rejection: two hops on one machine
//     collapse separation even under different node IDs or ports);
//   - distinct operator keys (same-box rejection via shared WireGuard key);
//   - per-hop latency budget with a fast/safe tradeoff knob.
//
// The builder validates, it never dials: data-plane programming stays with
// the tunnel / routing / firewall owners. Secrets never appear here.
package multihop

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Hop is one circuit position: public dial data only, never secrets.
// OperatorKey is the node's WireGuard public key, used as the operator
// identity proxy for same-box detection.
type Hop struct {
	NodeID       string  `json:"node_id"`
	Country      string  `json:"country"`
	Endpoint     string  `json:"endpoint"`
	OperatorKey  string  `json:"operator_key"`
	PricePerHour float64 `json:"price_per_hour_dero"`
}

// Route is an ordered entry -> ... -> exit path. Hops[0] is the entry
// (guard position); Hops[len-1] is the exit. EntryPinned records whether
// the entry is a sticky guard: rotation must then swap downstream hops
// only, never the entry.
type Route struct {
	ID          string    `json:"id"`
	Hops        []Hop     `json:"hops"`
	EntryPinned bool      `json:"entry_pinned"`
	CreatedAt   time.Time `json:"created_at"`
}

// Tradeoff selects the latency/separation bias for route construction.
// "fast" caps per-hop latency tightly; "safe" tolerates slower hops to
// gain separation; "balanced" (default) applies no latency cap.
type Tradeoff string

const (
	TradeoffFast     Tradeoff = "fast"
	TradeoffBalanced Tradeoff = "balanced"
	TradeoffSafe     Tradeoff = "safe"
)

// Latency budgets in milliseconds. Fast keeps interactive latency low;
// safe accepts slow hops so distant/diverse nodes stay eligible.
const (
	FastLatencyBudgetMs = 150
	SafeLatencyBudgetMs = 800
)

// BuildOptions tunes BuildRoute. Zero value = up to 3 hops, balanced.
type BuildOptions struct {
	// MaxHops caps the path length (1-3). Zero means 3.
	MaxHops int
	// Tradeoff selects the latency budget preset. Empty means balanced.
	Tradeoff Tradeoff
	// MaxLatencyMs overrides the tradeoff preset per hop. Measured node
	// latency above the budget rejects the route. Zero disables the cap.
	// Unmeasured nodes (Latency == 0) are never rejected by budget.
	MaxLatencyMs float64
	// RequireDiverseCountries rejects multi-hop routes whose hops share
	// a country. Off by default; the safe selector prefers diversity
	// without hard-failing small pools.
	RequireDiverseCountries bool
}

// BudgetMs resolves the effective per-hop latency cap in milliseconds,
// or 0 when uncapped.
func (o BuildOptions) BudgetMs() float64 {
	if o.MaxLatencyMs > 0 {
		return o.MaxLatencyMs
	}
	switch o.Tradeoff {
	case TradeoffFast:
		return FastLatencyBudgetMs
	case TradeoffSafe:
		return SafeLatencyBudgetMs
	default:
		return 0
	}
}

// BuildRoute validates nodes as an ordered entry -> ... -> exit path and
// returns the canonical Route. The hop count is len(nodes) (1-3); MaxHops
// caps it. Every rejection names the offending node and the fix.
func BuildRoute(nodes []NodeInfo, opts BuildOptions) (*Route, error) {
	max := opts.MaxHops
	if max <= 0 {
		max = 3
	}
	if max > 3 {
		max = 3
	}
	if len(nodes) == 0 {
		return nil, errors.New("multihop: route needs at least 1 hop (connect a node first)")
	}
	if len(nodes) > max {
		return nil, fmt.Errorf("multihop: %d hops exceeds the %d-hop cap (drop a hop)", len(nodes), max)
	}
	if len(nodes) > 3 {
		return nil, fmt.Errorf("multihop: %d hops exceeds the 3-hop cap (drop a hop)", len(nodes))
	}
	for i, n := range nodes {
		if err := n.Validate(); err != nil {
			return nil, fmt.Errorf("multihop: hop %d invalid: %w", i+1, err)
		}
	}
	if err := checkDistinct(nodes); err != nil {
		return nil, err
	}
	if budget := opts.BudgetMs(); budget > 0 {
		for _, n := range nodes {
			if n.Latency > 0 && n.Latency > budget {
				return nil, fmt.Errorf("multihop: node %q RTT %.0fms exceeds the %.0fms per-hop budget (use the safe tradeoff or pick a faster node)", n.NodeID, n.Latency, budget)
			}
		}
	}
	if opts.RequireDiverseCountries && len(nodes) > 1 {
		seen := make(map[string]string)
		for _, n := range nodes {
			c := strings.ToUpper(strings.TrimSpace(n.Country))
			if c == "" {
				continue
			}
			if prev, dup := seen[c]; dup {
				return nil, fmt.Errorf("multihop: hops %q and %q share country %q (pick nodes in distinct countries for safe mode)", prev, n.NodeID, c)
			}
			seen[c] = n.NodeID
		}
	}
	hops := make([]Hop, len(nodes))
	for i, n := range nodes {
		hops[i] = Hop{
			NodeID:       n.NodeID,
			Country:      n.Country,
			Endpoint:     n.Endpoint,
			OperatorKey:  n.WGPubKey,
			PricePerHour: n.PricePerHour,
		}
	}
	return &Route{
		ID:        newID(),
		Hops:      hops,
		CreatedAt: time.Now().UTC(),
	}, nil
}

// checkDistinct rejects loops (repeated node ID) and same-box hops
// (shared endpoint host or shared operator key). It is shared by Route,
// Circuit, and the legacy 3-hop builder so every path enforces the same
// separation invariant.
func checkDistinct(nodes []NodeInfo) error {
	seenID := make(map[string]bool, len(nodes))
	seenHost := make(map[string]string, len(nodes))
	seenKey := make(map[string]string, len(nodes))
	for _, n := range nodes {
		if seenID[n.NodeID] {
			return fmt.Errorf("multihop: loop rejected: node %q appears twice (each hop must be a distinct node)", n.NodeID)
		}
		seenID[n.NodeID] = true
		host := endpointHost(n.Endpoint)
		if prev, dup := seenHost[host]; dup {
			return fmt.Errorf("multihop: same-box rejected: %q and %q share endpoint host %q (hops must run on distinct machines)", prev, n.NodeID, host)
		}
		seenHost[host] = n.NodeID
		if n.WGPubKey != "" {
			if prev, dup := seenKey[n.WGPubKey]; dup {
				return fmt.Errorf("multihop: same-box rejected: %q and %q share an operator key (hops must have distinct operators)", prev, n.NodeID)
			}
			seenKey[n.WGPubKey] = n.NodeID
		}
	}
	return nil
}

// endpointHost normalises an endpoint to its host for same-box comparison:
// same IP under different ports is still one box.
func endpointHost(ep string) string {
	if h, _, err := net.SplitHostPort(ep); err == nil {
		return strings.ToLower(strings.TrimSpace(h))
	}
	return strings.ToLower(strings.TrimSpace(ep))
}

// Verify re-checks a constructed route: hop count, per-hop dial data,
// and the distinctness invariant. The data plane owner calls Verify
// before programming any segment.
func (r *Route) Verify() error {
	if r == nil {
		return errors.New("multihop: nil route")
	}
	if r.ID == "" {
		return errors.New("multihop: route id empty")
	}
	if len(r.Hops) == 0 || len(r.Hops) > 3 {
		return fmt.Errorf("multihop: route hop count must be 1..3, got %d", len(r.Hops))
	}
	nodes := make([]NodeInfo, len(r.Hops))
	for i, h := range r.Hops {
		if h.NodeID == "" {
			return fmt.Errorf("multihop: hop %d missing node id", i+1)
		}
		if h.Endpoint == "" {
			return fmt.Errorf("multihop: hop %q missing endpoint", h.NodeID)
		}
		nodes[i] = NodeInfo{NodeID: h.NodeID, WGPubKey: h.OperatorKey, Endpoint: h.Endpoint}
		if h.OperatorKey == "" {
			// Stored routes pre-dating the operator-key check skip only
			// the key leg; ID + endpoint legs still apply.
			continue
		}
	}
	// Re-run full distinctness when keys are present, else the ID/host legs.
	full := true
	for _, n := range nodes {
		if n.WGPubKey == "" {
			full = false
		}
	}
	if full {
		return checkDistinct(nodes)
	}
	seenID := make(map[string]bool, len(nodes))
	seenHost := make(map[string]string, len(nodes))
	for _, n := range nodes {
		if seenID[n.NodeID] {
			return fmt.Errorf("multihop: loop rejected: node %q appears twice", n.NodeID)
		}
		seenID[n.NodeID] = true
		if host := endpointHost(n.Endpoint); host != "" {
			if prev, dup := seenHost[host]; dup {
				return fmt.Errorf("multihop: same-box rejected: %q and %q share endpoint host %q", prev, n.NodeID, host)
			}
			seenHost[host] = n.NodeID
		}
	}
	return nil
}

// Len returns the hop count.
func (r *Route) Len() int { return len(r.Hops) }

// Entry returns the first hop (guard position).
func (r *Route) Entry() Hop { return r.Hops[0] }

// Exit returns the last hop (egress position).
func (r *Route) Exit() Hop { return r.Hops[len(r.Hops)-1] }

// NodeIDs returns the ordered hop node IDs.
func (r *Route) NodeIDs() []string {
	out := make([]string, len(r.Hops))
	for i, h := range r.Hops {
		out[i] = h.NodeID
	}
	return out
}

// Countries returns the per-hop countries in path order.
func (r *Route) Countries() []string {
	out := make([]string, len(r.Hops))
	for i, h := range r.Hops {
		out[i] = h.Country
	}
	return out
}

// TotalPricePerHour sums the per-hop session rates.
func (r *Route) TotalPricePerHour() float64 {
	var total float64
	for _, h := range r.Hops {
		total += h.PricePerHour
	}
	return total
}
