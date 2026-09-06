package app

import (
	"errors"
	"time"

	"github.com/dero-veilnet/veilnet/internal/config"
	"github.com/dero-veilnet/veilnet/internal/events"
	"github.com/dero-veilnet/veilnet/internal/multihop"
)

// Circuit is a 1-3 hop path: Hops[0] is the entry (guard position),
// Hops[len-1] the exit. EntryID/ExitID are kept for single/2-hop
// readers; MiddleID is set on 3-hop circuits. Countries and Prices run
// parallel to Hops for UI display. GuardPinned records the sticky entry:
// while pinned, RotateCircuit swaps downstream hops only, never the
// entry, so the client IP is never exposed to a new observer.
type Circuit struct {
	Active      bool
	EntryID     string
	MiddleID    string
	ExitID      string
	Hops        []string
	Countries   []string
	Prices      []float64
	GuardPinned bool
	GuardSince  time.Time
	BuiltAt     time.Time
	Rotations   int
}

// CircuitRotated is the CIRCUIT_ROTATED event payload: hop countries
// included so the UI renders the chain without another round-trip.
type CircuitRotated struct {
	Path        string
	Hops        []string
	Countries   []string
	Rotations   int
	GuardPinned bool
}

// GuardDue reports whether the pinned guard reached the 30-day sticky
// lifetime and is eligible for replacement (manual reset + rebuild).
func (c Circuit) GuardDue(now time.Time) bool {
	if !c.GuardPinned || c.EntryID == "" {
		return false
	}
	if c.GuardSince.IsZero() {
		return true
	}
	return !now.Before(c.GuardSince.Add(multihop.DefaultGuardRotationInterval))
}

func mhNode(n NodeInfo) multihop.NodeInfo {
	return multihop.NodeInfo{
		NodeID: n.NodeID, WGPubKey: n.WGPubkey, Endpoint: n.Endpoint,
		Region: n.Region, Country: n.Country, City: n.City,
		PricePerHour: n.PricePerHourDero, Load: n.Load,
		Latency: float64(n.LatencyMs), Uptime: 1, History: n.Trust,
	}
}

// setCircuit records hops (already validated) as the active circuit,
// pins the entry guard, and publishes CIRCUIT_ROTATED with hop countries.
func (a *App) setCircuit(nodes []NodeInfo) {
	hops := make([]string, len(nodes))
	countries := make([]string, len(nodes))
	prices := make([]float64, len(nodes))
	for i, n := range nodes {
		hops[i], countries[i], prices[i] = n.NodeID, n.Country, n.PricePerHourDero
	}
	c := Circuit{Active: true, Hops: hops, Countries: countries, Prices: prices, BuiltAt: time.Now()}
	if len(nodes) > 0 {
		c.EntryID = nodes[0].NodeID
		c.ExitID = nodes[len(nodes)-1].NodeID
		c.GuardPinned = true
		c.GuardSince = time.Now()
	}
	if len(nodes) == 3 {
		c.MiddleID = nodes[1].NodeID
	}
	a.mu.Lock()
	c.Rotations = a.circuit.Rotations
	if a.circuit.Active && len(a.circuit.Hops) > 0 && a.circuit.Hops[0] == c.Hops[0] {
		// Guard preserved across rebuilds: keep continuity, not just the id.
		c.GuardSince = a.circuit.GuardSince
		if c.GuardSince.IsZero() {
			c.GuardSince = c.BuiltAt
		}
	}
	a.circuit = c
	snap := a.circuit
	a.mu.Unlock()
	path := ""
	for i, h := range snap.Hops {
		if i > 0 {
			path += "->"
		}
		path += h
	}
	events.Publish(events.CIRCUIT_ROTATED, CircuitRotated{
		Path: path, Hops: snap.Hops, Countries: snap.Countries,
		Rotations: snap.Rotations, GuardPinned: snap.GuardPinned,
	})
}

// BuildCircuit selects entry+exit and records the 2-hop path. The caller
// must already be connected; the exit becomes the current node.
func (a *App) BuildCircuit(entryID, exitID string) error {
	return a.BuildCircuitHops(entryID, exitID)
}

// BuildCircuit3 records the full entry -> middle -> exit path. The caller
// must already be connected.
func (a *App) BuildCircuit3(entryID, middleID, exitID string) error {
	return a.BuildCircuitHops(entryID, middleID, exitID)
}

// BuildCircuitHops records a 1-3 hop path from explicit node ids.
// Distinct nodes on distinct boxes are enforced (loop + same-box
// rejection); violations name the fix. The entry guard pins on success.
func (a *App) BuildCircuitHops(ids ...string) error {
	a.mu.RLock()
	connected := a.node != nil
	a.mu.RUnlock()
	if !connected {
		return errors.New("connect first: circuit needs a live session")
	}
	if len(ids) == 0 || len(ids) > 3 {
		return errors.New("pass 1-3 node ids, or use auto-build for automatic selection")
	}
	nodes := make([]NodeInfo, len(ids))
	for i, id := range ids {
		n, err := a.findNode(id)
		if err != nil {
			return err
		}
		nodes[i] = n
	}
	mh := make([]multihop.NodeInfo, len(nodes))
	for i, n := range nodes {
		mh[i] = mhNode(n)
	}
	if _, err := multihop.BuildRoute(mh, multihop.BuildOptions{}); err != nil {
		return err
	}
	a.setCircuit(nodes)
	return nil
}

// AutoCircuit builds a 2-hop path honoring entry-region config: the current
// node becomes the exit and a different-region node the entry when possible.
func (a *App) AutoCircuit() error {
	return a.AutoCircuitHops(2)
}

// AutoCircuitHops builds an n-hop (1-3) path automatically: the current
// node anchors the exit and the best-scoring distinct nodes fill entry
// (region-preferred) and middle. Every hop is separation-checked; thin
// pools yield the longest feasible path instead of an error.
func (a *App) AutoCircuitHops(n int) error {
	if n <= 0 {
		n = 2
	}
	if n > 3 {
		n = 3
	}
	a.mu.RLock()
	var exitID, wantEntry string
	if a.node != nil {
		exitID = a.node.NodeID
	}
	wantEntry = a.cfg.Multihop.EntryRegion
	a.mu.RUnlock()
	if exitID == "" {
		return errors.New("connect first: circuit needs a live session")
	}
	exit, err := a.findNode(exitID)
	if err != nil {
		return err
	}
	nodes, err := a.ListNodes()
	if err != nil {
		return err
	}
	exclude := map[string]bool{exitID: true}
	path := make([]NodeInfo, 0, n)
	path = append(path, exit) // anchored exit; entry prepended below
	// Entry first (region-preferred), then middle, so Hops[0] is guarded.
	for len(path) < n {
		want := ""
		if len(path) == 1 {
			want = wantEntry
		}
		next, err := a.bestExcept(nodes, exclude, want)
		if err != nil {
			break
		}
		path = append([]NodeInfo{next}, path...)
		exclude[next.NodeID] = true
	}
	if len(path) < 2 && n > 1 {
		return errors.New("no second hop available (need a distinct node on a distinct box)")
	}
	mh := make([]multihop.NodeInfo, len(path))
	for i, x := range path {
		mh[i] = mhNode(x)
	}
	// Enforce separation; drop the middle first when the pool is thin.
	for {
		if _, err := multihop.BuildRoute(mh, multihop.BuildOptions{}); err == nil {
			break
		}
		if len(path) <= 1 {
			return errors.New("pool cannot form a separated path (nodes share boxes or keys)")
		}
		// Drop middle (index 1) to keep the region-preferred entry + exit.
		path = append(path[:1], path[2:]...)
		mh = append(mh[:1], mh[2:]...)
	}
	a.setCircuit(path)
	return nil
}

// bestExcept scores provider candidates under the configured policy,
// skipping excluded/inactive/repeatedly-failing nodes. wantRegion, when
// non-empty, prefers that region for the pick (entry preference) and falls
// back to any region when it yields nothing.
func (a *App) bestExcept(nodes []NodeInfo, exclude map[string]bool, wantRegion string) (NodeInfo, error) {
	a.mu.RLock()
	policy := a.cfg.Network.SelectPolicy
	a.mu.RUnlock()
	if policy == "" {
		policy = config.SelectFastest
	}
	for pass := range 2 {
		var cands []NodeInfo
		for _, n := range nodes {
			if exclude[n.NodeID] {
				continue
			}
			if n.Status != "" && n.Status != "active" {
				continue
			}
			if n.FailCount >= 5 {
				continue
			}
			if pass == 0 && wantRegion != "" && n.Region != wantRegion {
				continue
			}
			cands = append(cands, n)
		}
		if len(cands) == 0 {
			continue
		}
		best := cands[0]
		bestScore := score(policy, best, nodes)
		for _, n := range cands[1:] {
			if s := score(policy, n, nodes); s > bestScore {
				best, bestScore = n, s
			}
		}
		return best, nil
	}
	return NodeInfo{}, errors.New("no suitable nodes available")
}

// RotateCircuit picks a fresh exit (auto-select), moves the engine endpoint,
// and keeps the session. Guard-aware: the entry (and middle on 3-hop
// circuits) never changes here, so rotation never exposes the client IP
// to a new entry observer. Emits CIRCUIT_ROTATED with hop countries.
func (a *App) RotateCircuit() error {
	a.mu.RLock()
	circ := a.circuit
	engine := a.engine
	a.mu.RUnlock()
	if engine == nil {
		return errors.New("no tunnel engine wired")
	}
	nodes, err := a.ListNodes()
	if err != nil {
		return err
	}
	kept := map[string]bool{}
	for _, h := range circ.Hops {
		kept[h] = true
	}
	a.mu.RLock()
	connected := a.node != nil
	a.mu.RUnlock()
	if !connected && len(circ.Hops) == 0 {
		return errors.New("connect first: circuit needs a live session")
	}
	next, err := a.bestExcept(nodes, kept, "")
	if err != nil {
		return errors.New("no fresh exit available (pool exhausted; try again later)")
	}
	// Separation-check the rotated path before touching the data plane.
	var keptNodes []NodeInfo
	if len(circ.Hops) > 1 {
		for _, h := range circ.Hops[:len(circ.Hops)-1] {
			n, err := a.findNode(h)
			if err != nil {
				return err
			}
			keptNodes = append(keptNodes, n)
		}
	}
	mh := make([]multihop.NodeInfo, 0, len(keptNodes)+1)
	for _, k := range keptNodes {
		mh = append(mh, mhNode(k))
	}
	mh = append(mh, mhNode(next))
	if _, err := multihop.BuildRoute(mh, multihop.BuildOptions{}); err != nil {
		return err
	}
	if err := engine.RotateEndpoint(next.Endpoint); err != nil {
		return err
	}
	a.mu.Lock()
	if len(a.circuit.Hops) > 1 {
		a.circuit.Hops[len(a.circuit.Hops)-1] = next.NodeID
		a.circuit.Countries[len(a.circuit.Countries)-1] = next.Country
		a.circuit.Prices[len(a.circuit.Prices)-1] = next.PricePerHourDero
		a.circuit.ExitID = next.NodeID
	} else {
		a.circuit.Hops = []string{next.NodeID}
		a.circuit.Countries = []string{next.Country}
		a.circuit.Prices = []float64{next.PricePerHourDero}
		a.circuit.EntryID = next.NodeID
		a.circuit.ExitID = next.NodeID
		a.circuit.GuardPinned = false
	}
	a.circuit.Active = true
	if a.circuit.BuiltAt.IsZero() {
		a.circuit.BuiltAt = time.Now()
	}
	a.circuit.Rotations++
	if a.node != nil {
		*a.node = next
	}
	snap := a.circuit
	a.mu.Unlock()
	path := ""
	for i, h := range snap.Hops {
		if i > 0 {
			path += "->"
		}
		path += h
	}
	events.Publish(events.CIRCUIT_ROTATED, CircuitRotated{
		Path: path, Hops: snap.Hops, Countries: snap.Countries,
		Rotations: snap.Rotations, GuardPinned: snap.GuardPinned,
	})
	return nil
}

// ResetGuard clears the sticky entry pin (manual user action): the next
// rotation or rebuild may select a fresh entry. It never touches tunnels.
func (a *App) ResetGuard() {
	a.mu.Lock()
	a.circuit.GuardPinned = false
	a.circuit.GuardSince = time.Time{}
	a.mu.Unlock()
}

// MaybeAutoRotate rotates when the configured interval elapsed. Returns
// true when a rotation happened.
func (a *App) MaybeAutoRotate(now time.Time) (bool, error) {
	a.mu.RLock()
	enabled := a.cfg.Multihop.Enabled
	interval := a.cfg.Multihop.RotateMinutes
	last := a.circuit.BuiltAt
	active := a.circuit.Active
	a.mu.RUnlock()
	if !enabled || !active || interval <= 0 {
		return false, nil
	}
	if now.Sub(last) < time.Duration(interval)*time.Minute {
		return false, nil
	}
	if err := a.RotateCircuit(); err != nil {
		return false, err
	}
	return true, nil
}
