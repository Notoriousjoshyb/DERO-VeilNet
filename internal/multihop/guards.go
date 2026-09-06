// Entry-guard pinning and guard-aware rotation.
//
// Rationale: without a sticky entry, every rotation exposes the client to
// a new entry hop that learns the client's real IP. An adversary running
// many nodes gets a fresh chance to observe the client on each rotation.
// Pinning the entry (guard) bounds that exposure: rotations swap the exit
// (or middle+exit) while the entry — the only hop that ever sees the
// client IP — stays stable for weeks. See docs/MULTIHOP.md.
//
// A pinned Route keeps Hops[0] across RotateExit / RotateDownstream.
// Unpinned routes may rotate fully via RotateAll. GuardSet is the sticky
// entry record: rotation interval defaults to 30 days, reset is manual.
package multihop

import (
	"errors"
	"fmt"
	"time"
)

// DefaultGuardRotationInterval is the sticky-entry lifetime: a pinned
// guard is kept this long before it becomes eligible for replacement.
// Default 30 days; there is no automatic silent swap — replacement still
// goes through a fresh explicit rotation.
const DefaultGuardRotationInterval = 30 * 24 * time.Hour

// GuardSet records the sticky entry hop. Pinned == false means no guard
// is active (fresh client or after a manual reset): any hop may rotate.
type GuardSet struct {
	EntryID  string        `json:"entry_id"`
	PinnedAt time.Time     `json:"pinned_at"`
	Interval time.Duration `json:"interval_ns"`
	Pinned   bool          `json:"pinned"`
}

// PinGuard sticks entry as the guard from now with the default interval.
func PinGuard(entry NodeInfo) GuardSet {
	return GuardSet{
		EntryID:  entry.NodeID,
		PinnedAt: time.Now().UTC(),
		Interval: DefaultGuardRotationInterval,
		Pinned:   entry.NodeID != "",
	}
}

// Reset clears the guard (manual user action): the next rotation may pick
// a fresh entry. It never touches the data plane.
func (g *GuardSet) Reset() {
	*g = GuardSet{}
}

// ShouldRotate reports whether the guard lifetime elapsed at now and the
// entry is eligible for replacement. Pinned entries younger than the
// interval must be kept.
func (g *GuardSet) ShouldRotate(now time.Time) bool {
	if g == nil || !g.Pinned || g.EntryID == "" {
		return false
	}
	iv := g.Interval
	if iv <= 0 {
		iv = DefaultGuardRotationInterval
	}
	since := g.PinnedAt
	if since.IsZero() {
		return true
	}
	return !now.Before(since.Add(iv))
}

// Guards reports whether g pins route r's entry: same entry ID, pinned,
// and not yet due for replacement.
func (g *GuardSet) Guards(r *Route) bool {
	if g == nil || !g.Pinned || r == nil || len(r.Hops) == 0 {
		return false
	}
	return g.EntryID == r.Hops[0].NodeID
}

// RotateExit swaps the EXIT hop, keeps every preceding hop (entry, and
// middle on 3-hop routes), rebuilds and verifies before committing.
// Single-hop routes rotate by replacing their single node. The guard
// entry is never exposed to a new observer: the client IP stays behind
// the same entry.
//
// On success the returned Route carries EntryPinned=true when the entry
// was preserved.
func (r *Route) RotateExit(newExit NodeInfo) (*Route, error) {
	if r == nil || len(r.Hops) == 0 {
		return nil, errors.New("multihop: no route to rotate (build one first)")
	}
	if err := newExit.Validate(); err != nil {
		return nil, fmt.Errorf("multihop: bad replacement exit: %w", err)
	}
	if len(r.Hops) == 1 {
		next, err := BuildRoute([]NodeInfo{newExit}, BuildOptions{})
		if err != nil {
			return nil, err
		}
		return next, nil
	}
	kept := make([]NodeInfo, 0, len(r.Hops))
	for _, h := range r.Hops[:len(r.Hops)-1] {
		kept = append(kept, NodeInfo{
			NodeID: h.NodeID, WGPubKey: h.OperatorKey, Endpoint: h.Endpoint,
		})
	}
	next, err := BuildRoute(append(kept, newExit), BuildOptions{})
	if err != nil {
		return nil, err
	}
	next.EntryPinned = true
	return next, nil
}

// RotateDownstream swaps MIDDLE+EXIT on a 3-hop route, keeps the guard
// entry, rebuilds and verifies. Rejected on 1-2 hop routes (use
// RotateExit there). The entry observer never changes.
func (r *Route) RotateDownstream(newMiddle, newExit NodeInfo) (*Route, error) {
	if r == nil || len(r.Hops) != 3 {
		return nil, errors.New("multihop: downstream rotation needs a 3-hop route (use RotateExit for shorter routes)")
	}
	if err := newMiddle.Validate(); err != nil {
		return nil, fmt.Errorf("multihop: bad replacement middle: %w", err)
	}
	if err := newExit.Validate(); err != nil {
		return nil, fmt.Errorf("multihop: bad replacement exit: %w", err)
	}
	entry := r.Hops[0]
	next, err := BuildRoute([]NodeInfo{
		{NodeID: entry.NodeID, WGPubKey: entry.OperatorKey, Endpoint: entry.Endpoint},
		newMiddle, newExit,
	}, BuildOptions{})
	if err != nil {
		return nil, err
	}
	next.EntryPinned = true
	return next, nil
}

// RotateAll replaces the whole path (unpinned mode): every hop, entry
// included, may change. The entry keeps its pinned flag only when the
// new path starts at the same entry node; otherwise the pin clears and
// the caller should PinGuard the new entry explicitly.
func (r *Route) RotateAll(newNodes []NodeInfo) (*Route, error) {
	if r == nil {
		return nil, errors.New("multihop: no route to rotate (build one first)")
	}
	next, err := BuildRoute(newNodes, BuildOptions{})
	if err != nil {
		return nil, err
	}
	if len(r.Hops) > 0 && len(next.Hops) > 0 && next.Hops[0].NodeID == r.Hops[0].NodeID {
		next.EntryPinned = r.EntryPinned
	}
	return next, nil
}

// RotateGuarded performs one guard-aware rotation step against a candidate
// pool: when g pins the route entry it swaps downstream hops only (exit,
// or middle+exit on 3-hop routes); otherwise it rebuilds the full path.
// pick selects one node from the eligible pool (already filtered to valid
// nodes); it is called once per replaced hop. Nodes colliding with kept
// hops are filtered before each pick, so a pick returning a loop/same-box
// node fails the rotation instead of corrupting the route.
func RotateGuarded(cur *Route, pool []NodeInfo, g *GuardSet, pick func([]NodeInfo) (NodeInfo, error)) (*Route, error) {
	if cur == nil || len(cur.Hops) == 0 {
		return nil, errors.New("multihop: no route to rotate (build one first)")
	}
	if pick == nil {
		return nil, errors.New("multihop: rotation needs a selection function")
	}
	eligible := make([]NodeInfo, 0, len(pool))
	for _, n := range pool {
		if n.Validate() == nil {
			eligible = append(eligible, n)
		}
	}
	if len(eligible) == 0 {
		return nil, errors.New("multihop: rotation pool has no valid nodes")
	}
	kept := map[string]bool{}
	for _, h := range cur.Hops {
		kept[h.NodeID] = true
	}
	if g != nil && g.Guards(cur) {
		// Pinned: keep the entry, replace downstream.
		switch len(cur.Hops) {
		case 1:
			next, err := pick(excludeNodes(eligible, kept))
			if err != nil {
				return nil, err
			}
			return cur.RotateExit(next)
		case 2:
			next, err := pick(excludeNodes(eligible, kept))
			if err != nil {
				return nil, err
			}
			return cur.RotateExit(next)
		default:
			midPool := excludeNodes(eligible, kept)
			mid, err := pick(midPool)
			if err != nil {
				return nil, err
			}
			kept[mid.NodeID] = true
			exit, err := pick(excludeNodes(eligible, kept))
			if err != nil {
				return nil, err
			}
			return cur.RotateDownstream(mid, exit)
		}
	}
	// Unpinned: rebuild the full path, one pick per hop.
	fresh := excludeNodes(eligible, nil)
	picked := make([]NodeInfo, 0, len(cur.Hops))
	taken := map[string]bool{}
	for range cur.Hops {
		n, err := pick(excludeNodes(fresh, taken))
		if err != nil {
			return nil, err
		}
		taken[n.NodeID] = true
		picked = append(picked, n)
	}
	return cur.RotateAll(picked)
}

func excludeNodes(pool []NodeInfo, skip map[string]bool) []NodeInfo {
	if len(skip) == 0 {
		return pool
	}
	out := make([]NodeInfo, 0, len(pool))
	for _, n := range pool {
		if !skip[n.NodeID] {
			out = append(out, n)
		}
	}
	return out
}
