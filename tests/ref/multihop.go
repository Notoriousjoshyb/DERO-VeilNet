package ref

import (
	"errors"
	"fmt"
)

// MaxHops caps circuits: v1 supports 1 hop, roadmap extends to 3.
const MaxHops = 3

// Route is an ordered node path: entry -> ... -> exit.
type Route struct {
	Hops []NodeMeta
}

// BuildRoute validates a candidate path: 1..MaxHops distinct eligible nodes
// with distinct endpoints (no loops, no same-box hops).
func BuildRoute(nodes []NodeMeta) (Route, error) {
	if len(nodes) == 0 || len(nodes) > MaxHops {
		return Route{}, fmt.Errorf("ref: hop count must be 1..%d", MaxHops)
	}
	seenNode := make(map[string]bool)
	seenEp := make(map[string]bool)
	for _, n := range nodes {
		if !Eligible(n) {
			return Route{}, fmt.Errorf("ref: hop %s ineligible", n.NodeID)
		}
		if seenNode[n.NodeID] {
			return Route{}, errors.New("ref: repeated node in circuit")
		}
		if seenEp[n.Endpoint] {
			return Route{}, errors.New("ref: repeated endpoint in circuit")
		}
		seenNode[n.NodeID] = true
		seenEp[n.Endpoint] = true
	}
	return Route{Hops: append([]NodeMeta(nil), nodes...)}, nil
}

// Exit returns the exit node (last hop) carrying user egress.
func (r Route) Exit() NodeMeta { return r.Hops[len(r.Hops)-1] }

// Rotate swaps the exit hop for a fresh eligible node, preserving entry
// hops, and reports the new route. Entry-preserving rotation limits
// guard-visibility churn while changing exit identity.
func (r Route) Rotate(pool []NodeMeta, pick func([]NodeMeta) (NodeMeta, error)) (Route, error) {
	if len(r.Hops) == 0 {
		return Route{}, errors.New("ref: empty route")
	}
	next, err := pick(pool)
	if err != nil {
		return Route{}, err
	}
	candidate := append(append([]NodeMeta(nil), r.Hops[:len(r.Hops)-1]...), next)
	return BuildRoute(candidate)
}
