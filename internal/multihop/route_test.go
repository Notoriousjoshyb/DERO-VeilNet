package multihop

import (
	"strings"
	"testing"
	"time"
)

func testNodes() []NodeInfo {
	mk := func(id, key, ep, country string, lat float64) NodeInfo {
		return NodeInfo{
			NodeID: id, WGPubKey: key, Endpoint: ep,
			Country: country, Region: "eu", PricePerHour: 0.05,
			Latency: lat, Uptime: 0.99, History: 0.9,
		}
	}
	return []NodeInfo{
		mk("n1", strings.Repeat("a", 44), "203.0.113.1:51820", "DE", 20),
		mk("n2", strings.Repeat("b", 44), "203.0.113.2:51820", "FR", 35),
		mk("n3", strings.Repeat("c", 44), "203.0.113.3:51820", "NL", 50),
		mk("n4", strings.Repeat("d", 44), "203.0.113.4:51820", "SE", 60),
	}
}

func TestBuildRouteThreeHop(t *testing.T) {
	nodes := testNodes()
	r, err := BuildRoute(nodes[:3], BuildOptions{})
	if err != nil {
		t.Fatalf("BuildRoute: %v", err)
	}
	if len(r.Hops) != 3 {
		t.Fatalf("hops = %d, want 3", len(r.Hops))
	}
	if r.Exit().NodeID != "n3" || r.Entry().NodeID != "n1" {
		t.Fatalf("entry/exit = %s/%s", r.Entry().NodeID, r.Exit().NodeID)
	}
	if err := r.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := r.Countries(); len(got) != 3 || got[0] != "DE" || got[2] != "NL" {
		t.Fatalf("countries = %v", got)
	}
}

func TestBuildRouteHopCounts(t *testing.T) {
	nodes := testNodes()
	for _, n := range []int{1, 2, 3} {
		r, err := BuildRoute(nodes[:n], BuildOptions{})
		if err != nil {
			t.Fatalf("%d-hop BuildRoute: %v", n, err)
		}
		if err := r.Verify(); err != nil {
			t.Fatalf("%d-hop Verify: %v", n, err)
		}
	}
	if _, err := BuildRoute(nil, BuildOptions{}); err == nil {
		t.Fatal("empty route accepted")
	}
	if _, err := BuildRoute(nodes, BuildOptions{}); err == nil { // 4 nodes
		t.Fatal("4-hop route accepted (cap is 3)")
	}
	if _, err := BuildRoute(nodes[:3], BuildOptions{MaxHops: 2}); err == nil {
		t.Fatal("3 nodes accepted with MaxHops=2")
	}
}

func TestBuildRouteRejectsLoop(t *testing.T) {
	nodes := testNodes()
	dup := []NodeInfo{nodes[0], nodes[1], nodes[0]}
	if _, err := BuildRoute(dup, BuildOptions{}); err == nil {
		t.Fatal("repeated node accepted (loop)")
	} else if !strings.Contains(err.Error(), "loop") {
		t.Fatalf("loop error should say loop: %v", err)
	}
}

func TestBuildRouteRejectsSameBoxEndpoint(t *testing.T) {
	nodes := testNodes()
	twin := nodes[1]
	twin.NodeID = "n2-twin"
	twin.WGPubKey = strings.Repeat("z", 44)
	twin.Endpoint = nodes[0].Endpoint // same machine, different id/key
	if _, err := BuildRoute([]NodeInfo{nodes[0], twin}, BuildOptions{}); err == nil {
		t.Fatal("shared endpoint accepted (same-box)")
	} else if !strings.Contains(err.Error(), "same-box") {
		t.Fatalf("same-box error should say same-box: %v", err)
	}
	// Same host, different port: still one box.
	twin.Endpoint = "203.0.113.1:51821"
	if _, err := BuildRoute([]NodeInfo{nodes[0], twin}, BuildOptions{}); err == nil {
		t.Fatal("shared endpoint host accepted (same-box)")
	}
}

func TestBuildRouteRejectsSameOperatorKey(t *testing.T) {
	nodes := testNodes()
	twin := nodes[1]
	twin.NodeID = "n2-twin"
	twin.Endpoint = "198.51.100.9:51820"
	twin.WGPubKey = nodes[0].WGPubKey // same operator key, distinct id/host
	if _, err := BuildRoute([]NodeInfo{nodes[0], twin}, BuildOptions{}); err == nil {
		t.Fatal("shared operator key accepted (same-box)")
	}
}

func TestBuildRouteLatencyBudget(t *testing.T) {
	nodes := testNodes()
	if _, err := BuildRoute(nodes[:2], BuildOptions{Tradeoff: TradeoffFast}); err != nil {
		t.Fatalf("fast budget should pass 20/35ms hops: %v", err)
	}
	slow := nodes[0]
	slow.Latency = 500
	if _, err := BuildRoute([]NodeInfo{slow, nodes[1]}, BuildOptions{Tradeoff: TradeoffFast}); err == nil {
		t.Fatal("500ms hop accepted under fast budget")
	}
	// Safe tolerates the slow hop.
	if _, err := BuildRoute([]NodeInfo{slow, nodes[1]}, BuildOptions{Tradeoff: TradeoffSafe}); err != nil {
		t.Fatalf("safe should tolerate 500ms: %v", err)
	}
	// Unmeasured nodes never trip the budget.
	unmeasured := nodes[0]
	unmeasured.Latency = 0
	if _, err := BuildRoute([]NodeInfo{unmeasured}, BuildOptions{Tradeoff: TradeoffFast}); err != nil {
		t.Fatalf("unmeasured node rejected by budget: %v", err)
	}
}

func TestRotateExitKeepsEntry(t *testing.T) {
	nodes := testNodes()
	r, err := BuildRoute(nodes[:2], BuildOptions{})
	if err != nil {
		t.Fatalf("BuildRoute: %v", err)
	}
	next, err := r.RotateExit(nodes[2])
	if err != nil {
		t.Fatalf("RotateExit: %v", err)
	}
	if next.Entry().NodeID != "n1" {
		t.Fatalf("entry changed: %v", next.NodeIDs())
	}
	if next.Exit().NodeID != "n3" {
		t.Fatalf("exit = %s, want n3", next.Exit().NodeID)
	}
	if !next.EntryPinned {
		t.Fatal("exit rotation should mark the entry pinned")
	}
	if err := next.Verify(); err != nil {
		t.Fatalf("Verify rotated: %v", err)
	}
	// Rotating onto the entry is a loop and must fail.
	if _, err := r.RotateExit(nodes[0]); err == nil {
		t.Fatal("rotation into loop accepted")
	}
}

func TestRotateDownstreamKeepsEntry(t *testing.T) {
	nodes := testNodes()
	r, err := BuildRoute(nodes[:3], BuildOptions{})
	if err != nil {
		t.Fatalf("BuildRoute: %v", err)
	}
	next, err := r.RotateDownstream(testNodeTwin(nodes[1], "n2b", "b", 101), nodes[3])
	if err != nil {
		t.Fatalf("RotateDownstream: %v", err)
	}
	if next.Exit().NodeID != "n4" {
		t.Fatalf("exit = %s, want n4", next.Exit().NodeID)
	}
	if err := next.Verify(); err != nil {
		t.Fatalf("Verify rotated: %v", err)
	}
	// Rejected on 2-hop routes.
	r2, _ := BuildRoute(nodes[:2], BuildOptions{})
	if _, err := r2.RotateDownstream(nodes[2], nodes[3]); err == nil {
		t.Fatal("downstream rotation accepted on 2-hop route")
	}
}

func testNodeTwin(n NodeInfo, id, keyChar string, octet int) NodeInfo {
	n.NodeID = id
	n.WGPubKey = strings.Repeat(keyChar, 44)
	n.Endpoint = "192.0.2." + itoa(octet) + ":51820"
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestGuardSetLifecycle(t *testing.T) {
	nodes := testNodes()
	g := PinGuard(nodes[0])
	if !g.Pinned || g.EntryID != "n1" {
		t.Fatalf("guard = %+v", g)
	}
	if g.ShouldRotate(time.Now()) {
		t.Fatal("fresh guard should not be due")
	}
	aged := g
	aged.PinnedAt = time.Now().Add(-31 * 24 * time.Hour)
	if !aged.ShouldRotate(time.Now()) {
		t.Fatal("31-day guard should be due")
	}
	aged.Reset()
	if aged.Pinned {
		t.Fatal("reset guard still pinned")
	}
}

func TestRotateGuardedPinnedKeepsEntry(t *testing.T) {
	nodes := testNodes()
	r, err := BuildRoute(nodes[:3], BuildOptions{})
	if err != nil {
		t.Fatalf("BuildRoute: %v", err)
	}
	g := PinGuard(nodes[0])
	if !g.Guards(r) {
		t.Fatal("guard should pin the route entry")
	}
	first := func(pool []NodeInfo) (NodeInfo, error) { return pool[0], nil }
	pool := append(append([]NodeInfo(nil), nodes[1:]...),
		testNodeTwin(nodes[1], "n2b", "q", 101), testNodeTwin(nodes[3], "n4b", "w", 102))
	next, err := RotateGuarded(r, pool, &g, first)
	if err != nil {
		t.Fatalf("RotateGuarded: %v", err)
	}
	if next.Entry().NodeID != "n1" {
		t.Fatalf("pinned rotation changed entry: %v", next.NodeIDs())
	}
	if err := next.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestRotateGuardedUnpinnedRotatesAll(t *testing.T) {
	nodes := testNodes()
	r, err := BuildRoute(nodes[:2], BuildOptions{})
	if err != nil {
		t.Fatalf("BuildRoute: %v", err)
	}
	g := GuardSet{} // no guard
	pick := func() func([]NodeInfo) (NodeInfo, error) {
		i := 0
		return func(pool []NodeInfo) (NodeInfo, error) {
			n := pool[i%len(pool)]
			i++
			return n, nil
		}
	}()
	next, err := RotateGuarded(r, nodes[2:], &g, pick)
	if err != nil {
		t.Fatalf("RotateGuarded: %v", err)
	}
	if err := next.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if next.Entry().NodeID == "n1" && next.Exit().NodeID == "n2" {
		t.Fatalf("unpinned rotation changed nothing: %v", next.NodeIDs())
	}
}

func TestSelectRouteTradeoffs(t *testing.T) {
	nodes := testNodes()
	agg := NewAggregator()
	for _, n := range nodes {
		agg.Observe(n, n.Latency)
	}
	fast, err := agg.SelectRoute(nodes, 3, TradeoffFast)
	if err != nil {
		t.Fatalf("SelectRoute fast: %v", err)
	}
	if len(fast) != 3 || fast[0].NodeID != "n1" {
		t.Fatalf("fast should lead with n1: %v", nodeIDs(fast))
	}
	safe, err := agg.SelectRoute(nodes, 3, TradeoffSafe)
	if err != nil {
		t.Fatalf("SelectRoute safe: %v", err)
	}
	if len(safe) != 3 {
		t.Fatalf("safe path = %v", nodeIDs(safe))
	}
	if _, err := BuildRoute(safe, BuildOptions{}); err != nil {
		t.Fatalf("safe selection fails BuildRoute: %v", err)
	}
	if _, err := agg.SelectRoute(nil, 3, TradeoffBalanced); err == nil {
		t.Fatal("empty pool accepted")
	}
}

func nodeIDs(ns []NodeInfo) []string {
	out := make([]string, len(ns))
	for i, n := range ns {
		out[i] = n.NodeID
	}
	return out
}

func TestThreeHopCircuitBuildVerify(t *testing.T) {
	nodes := testNodes()
	c, err := BuildThreeHopCircuit(nodes[0], nodes[1], nodes[2])
	if err != nil {
		t.Fatalf("BuildThreeHopCircuit: %v", err)
	}
	if c.Hops != 3 {
		t.Fatalf("hops = %d", c.Hops)
	}
	if err := c.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := c.Countries(); len(got) != 3 || got[1] != "FR" {
		t.Fatalf("countries = %v", got)
	}
	if len(c.Chain()) != 3 {
		t.Fatalf("chain len = %d", len(c.Chain()))
	}
	if c.MiddleConfig().NodeID != "n2" {
		t.Fatalf("middle = %q", c.MiddleConfig().NodeID)
	}
	// Same node twice rejected.
	if _, err := BuildThreeHopCircuit(nodes[0], nodes[0], nodes[2]); err == nil {
		t.Fatal("duplicate middle accepted")
	}
	// Corrupted hop count rejected.
	c.Hops = 3
	c.Middle = NodeInfo{}
	if err := c.Verify(); err == nil {
		t.Fatal("empty middle accepted")
	}
}

func TestRotatorExitKeepsGuard(t *testing.T) {
	nodes := testNodes()
	c, err := BuildThreeHopCircuit(nodes[0], nodes[1], nodes[2])
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var fired bool
	rt, err := NewRotator(c, func(old, next *Circuit) { fired = true })
	if err != nil {
		t.Fatalf("NewRotator: %v", err)
	}
	next, err := rt.RotateExit(nodes[3], "exit refresh")
	if err != nil {
		t.Fatalf("RotateExit: %v", err)
	}
	if next.Entry.NodeID != "n1" || next.Middle.NodeID != "n2" || next.Exit.NodeID != "n4" {
		t.Fatalf("rotation moved guard/middle: %s %s %s", next.Entry.NodeID, next.Middle.NodeID, next.Exit.NodeID)
	}
	if !fired {
		t.Fatal("OnRotated did not fire")
	}
	down, err := rt.RotateDownstream(testNodeTwin(nodes[1], "n2c", "q", 103), testNodeTwin(nodes[3], "n4c", "w", 104), "refresh")
	if err != nil {
		t.Fatalf("RotateDownstream: %v", err)
	}
	if down.Entry.NodeID != "n1" {
		t.Fatalf("downstream rotation moved entry: %s", down.Entry.NodeID)
	}
}
