package veilnettest

import (
	"strings"
	"testing"

	"github.com/dero-veilnet/veilnet/tests/ref"
)

func hopNodes() []ref.NodeMeta {
	key := strings.Repeat("k", 44)
	mk := func(id, ep string) ref.NodeMeta {
		return ref.NodeMeta{NodeID: id, WGPubkey: key, Region: "eu",
			Endpoint: ep, PricePerHour: 0.01, CapacityMax: 50,
			ProtocolVersion: 1, BondDero: 10, Status: "online", Version: "0.1.0"}
	}
	return []ref.NodeMeta{mk("n1", "203.0.113.1:51820"), mk("n2", "203.0.113.2:51820"), mk("n3", "203.0.113.3:51820")}
}

func TestBuildSingleHopRoute(t *testing.T) {
	r, err := ref.BuildRoute(hopNodes()[:1])
	if err != nil {
		t.Fatalf("BuildRoute: %v", err)
	}
	if r.Exit().NodeID != "n1" {
		t.Fatalf("exit = %s", r.Exit().NodeID)
	}
}

func TestBuildThreeHopRoute(t *testing.T) {
	r, err := ref.BuildRoute(hopNodes())
	if err != nil {
		t.Fatalf("BuildRoute: %v", err)
	}
	if len(r.Hops) != 3 || r.Exit().NodeID != "n3" {
		t.Fatalf("route = %+v", r)
	}
}

func TestRouteRejectsLoopsAndIneligible(t *testing.T) {
	nodes := hopNodes()
	dup := append(append([]ref.NodeMeta(nil), nodes[:2]...), nodes[0])
	if _, err := ref.BuildRoute(dup); err == nil {
		t.Fatal("repeated node accepted")
	}
	sameBox := append([]ref.NodeMeta(nil), nodes[0])
	twin := nodes[1]
	twin.NodeID = "n1-twin"
	twin.Endpoint = nodes[0].Endpoint
	sameBox = append(sameBox, twin)
	if _, err := ref.BuildRoute(sameBox); err == nil {
		t.Fatal("repeated endpoint accepted")
	}
	offline := append([]ref.NodeMeta(nil), nodes[0])
	offline[0].Status = "offline"
	if _, err := ref.BuildRoute(offline); err == nil {
		t.Fatal("offline hop accepted")
	}
	if _, err := ref.BuildRoute(nil); err == nil {
		t.Fatal("empty route accepted")
	}
	four := append(append([]ref.NodeMeta(nil), nodes...), nodes[0])
	_ = four
	oversized := []ref.NodeMeta{nodes[0], nodes[1], nodes[2],
		{NodeID: "n4", WGPubkey: strings.Repeat("k", 44), Endpoint: "203.0.113.4:51820",
			PricePerHour: 0.01, CapacityMax: 50, ProtocolVersion: 1, Status: "online"}}
	if _, err := ref.BuildRoute(oversized); err == nil {
		t.Fatal("4-hop circuit accepted (cap is 3)")
	}
}

func TestRouteRotateExitPreservesEntry(t *testing.T) {
	nodes := hopNodes()
	r, err := ref.BuildRoute(nodes[:2])
	if err != nil {
		t.Fatalf("BuildRoute: %v", err)
	}
	rotated, err := r.Rotate(nodes[2:], func(pool []ref.NodeMeta) (ref.NodeMeta, error) {
		return pool[0], nil
	})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotated.Hops[0].NodeID != "n1" {
		t.Fatalf("entry hop changed: %+v", rotated)
	}
	if rotated.Exit().NodeID != "n3" {
		t.Fatalf("exit = %s, want n3", rotated.Exit().NodeID)
	}
	// Rotating onto the current entry is a loop and must fail.
	if _, err := r.Rotate(nodes[:1], func(pool []ref.NodeMeta) (ref.NodeMeta, error) {
		return pool[0], nil
	}); err == nil {
		t.Fatal("rotation into loop accepted")
	}
}
