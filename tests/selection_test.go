package veilnettest

import (
	"strings"
	"testing"

	"github.com/dero-veilnet/veilnet/tests/ref"
)

func testNodes() []ref.NodeMeta {
	key := strings.Repeat("k", 44)
	return []ref.NodeMeta{
		{NodeID: "fast-cheap", WGPubkey: key, Region: "eu", Country: "DE", City: "Nuremberg",
			Endpoint: "203.0.113.1:51820", PricePerHour: 0.01, CapacityMax: 100, ClientsActive: 10,
			ProtocolVersion: 1, BondDero: 50, Status: "online", Version: "0.1.0"},
		{NodeID: "fast-pricey", WGPubkey: key, Region: "eu", Country: "DE", City: "Falkenstein",
			Endpoint: "203.0.113.2:51820", PricePerHour: 0.50, CapacityMax: 100, ClientsActive: 10,
			ProtocolVersion: 1, BondDero: 50, Status: "online", Version: "0.1.0"},
		{NodeID: "slow-cheap", WGPubkey: key, Region: "us", Country: "US", City: "Ashburn",
			Endpoint: "203.0.113.3:51820", PricePerHour: 0.01, CapacityMax: 100, ClientsActive: 10,
			ProtocolVersion: 1, BondDero: 50, Status: "online", Version: "0.1.0"},
		{NodeID: "full", WGPubkey: key, Region: "eu", Country: "NL", City: "Amsterdam",
			Endpoint: "203.0.113.4:51820", PricePerHour: 0.001, CapacityMax: 10, ClientsActive: 10,
			ProtocolVersion: 1, BondDero: 50, Status: "online", Version: "0.1.0"},
		{NodeID: "stale-proto", WGPubkey: key, Region: "eu", Country: "FR", City: "Paris",
			Endpoint: "203.0.113.5:51820", PricePerHour: 0.001, CapacityMax: 100, ClientsActive: 0,
			ProtocolVersion: 0, BondDero: 50, Status: "online", Version: "0.0.9"},
		{NodeID: "offline", WGPubkey: key, Region: "eu", Country: "SE", City: "Stockholm",
			Endpoint: "203.0.113.6:51820", PricePerHour: 0.001, CapacityMax: 100, ClientsActive: 0,
			ProtocolVersion: 1, BondDero: 50, Status: "offline", Version: "0.1.0"},
	}
}

func testSignals() map[string]ref.Signal {
	return map[string]ref.Signal{
		"fast-cheap":  {LatencyMS: 20, UptimePct: 99.9},
		"fast-pricey": {LatencyMS: 22, UptimePct: 99.9},
		"slow-cheap":  {LatencyMS: 180, UptimePct: 99.0},
		"full":        {LatencyMS: 5, UptimePct: 100},
		"stale-proto": {LatencyMS: 5, UptimePct: 100},
		"offline":     {LatencyMS: 5, UptimePct: 100},
	}
}

func TestSelectionPrefersFastCheapEligible(t *testing.T) {
	got := ref.Select(testNodes(), testSignals())
	if len(got) == 0 {
		t.Fatal("no node selected")
	}
	if got[0].NodeID != "fast-cheap" {
		t.Fatalf("best = %s, want fast-cheap", got[0].NodeID)
	}
	for _, n := range got {
		switch n.NodeID {
		case "full", "stale-proto", "offline":
			t.Fatalf("ineligible node %s selected", n.NodeID)
		}
	}
}

func TestSelectionExcludesAllWhenNoneEligible(t *testing.T) {
	nodes := testNodes()
	for i := range nodes {
		nodes[i].Status = "offline"
	}
	if got := ref.Select(nodes, testSignals()); len(got) != 0 {
		t.Fatalf("selected %d ineligible nodes", len(got))
	}
}

func TestSelectionPriceBeatsLatencyTie(t *testing.T) {
	nodes := []ref.NodeMeta{testNodes()[0], testNodes()[1]}
	signals := map[string]ref.Signal{
		"fast-cheap":  {LatencyMS: 20, UptimePct: 99.9},
		"fast-pricey": {LatencyMS: 20, UptimePct: 99.9},
	}
	got := ref.Select(nodes, signals)
	if len(got) != 2 || got[0].NodeID != "fast-cheap" {
		t.Fatalf("price tie-break failed: %+v", got)
	}
}

func TestSelectionHistoryAdjustsRanking(t *testing.T) {
	nodes := []ref.NodeMeta{testNodes()[0], testNodes()[1]}
	badHistory := map[string]ref.Signal{
		"fast-cheap":  {LatencyMS: 20, UptimePct: 99.9, HistoryBad: 10},
		"fast-pricey": {LatencyMS: 22, UptimePct: 99.9, HistoryGood: 20},
	}
	got := ref.Select(nodes, badHistory)
	if len(got) != 2 || got[0].NodeID != "fast-pricey" {
		t.Fatalf("local history ignored: %+v", got)
	}
}

func TestSelectionOverloadDeprioritized(t *testing.T) {
	nodes := testNodes()
	nodes[0].ClientsActive = 99 // fast-cheap nearly full
	signals := testSignals()
	got := ref.Select(nodes, signals)
	if len(got) == 0 {
		t.Fatal("no node selected")
	}
	// Load penalty (200 * ratio) must outweigh the latency gap.
	if got[0].NodeID == "fast-cheap" {
		t.Fatal("overloaded node still ranked first")
	}
}

func TestRegistryValidationRejectsSpoof(t *testing.T) {
	key := strings.Repeat("k", 44)
	base := testNodes()[0]
	cases := map[string]func(*ref.NodeMeta){
		"empty id":      func(n *ref.NodeMeta) { n.NodeID = "" },
		"empty wgkey":   func(n *ref.NodeMeta) { n.WGPubkey = "" },
		"short wgkey":   func(n *ref.NodeMeta) { n.WGPubkey = "short" },
		"empty endpoint": func(n *ref.NodeMeta) { n.Endpoint = "" },
		"negative price": func(n *ref.NodeMeta) { n.PricePerHour = -1 },
		"zero capacity": func(n *ref.NodeMeta) { n.CapacityMax = 0 },
		"bad status":    func(n *ref.NodeMeta) { n.Status = "super-online" },
	}
	_ = key
	for name, mutate := range cases {
		n := base
		mutate(&n)
		if err := ref.ValidateNode(n); err == nil {
			t.Fatalf("spoof case %q accepted", name)
		}
		if ref.Eligible(n) {
			t.Fatalf("spoof case %q eligible", name)
		}
	}
}
