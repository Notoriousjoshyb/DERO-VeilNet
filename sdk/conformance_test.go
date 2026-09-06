package veilnet_test

// Conformance: the same flow runs against fakes and against the real
// *app.App (demo wiring with FakeEngine). Both must pass.

import (
	"errors"
	"sync"
	"testing"

	veilnet "github.com/dero-veilnet/veilnet/sdk/veilnet"
	"github.com/dero-veilnet/veilnet/internal/app"
)

// fakeBackend is an in-memory Backend for the fakes leg.
type fakeBackend struct {
	mu        sync.Mutex
	nodes     []veilnet.Node
	connected string
}

func (f *fakeBackend) ListNodes() ([]veilnet.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]veilnet.Node(nil), f.nodes...), nil
}

func (f *fakeBackend) Connect(nodeID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.nodes {
		if n.NodeID == nodeID {
			f.connected = nodeID
			return nil
		}
	}
	return errors.New("unknown node")
}

func (f *fakeBackend) Disconnect() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connected = ""
	return nil
}

func (f *fakeBackend) Observe() (veilnet.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.connected == "" {
		return veilnet.Status{EngineState: "DOWN"}, nil
	}
	return veilnet.Status{Connected: true, EngineState: "UP", NodeID: f.connected}, nil
}

func (f *fakeBackend) Diagnose() (veilnet.Diagnostics, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return veilnet.Diagnostics{
		Connected:   f.connected != "",
		EngineState: map[bool]string{true: "UP", false: "DOWN"}[f.connected != ""],
		NodeID:      f.connected,
		Checks:      map[string]string{"tunnel": "ok:up"},
	}, nil
}

func fakeNodes() []veilnet.Node {
	return []veilnet.Node{
		{NodeID: "cheap", Region: "eu", PricePerHourDERO: 0.1, LatencyMs: 50, Status: "active"},
		{NodeID: "pricey", Region: "eu", PricePerHourDERO: 0.9, LatencyMs: 5, Status: "active"},
		{NodeID: "dead", Region: "eu", PricePerHourDERO: 0.01, Status: "disabled"},
	}
}

// runConformance exercises Discover/Select/Quote/Connect/Status/
// Diagnostics/Disconnect against any Backend.
func runConformance(t *testing.T, c *veilnet.Client) {
	t.Helper()

	nodes, err := c.Discover()
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(nodes) == 0 {
		t.Fatal("Discover: no nodes")
	}

	best, err := c.Select()
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if best.NodeID == "dead" {
		t.Fatal("Select picked a disabled node")
	}

	q := c.Quote(best, 2)
	if q.Hours != 2 || q.AmountDERO != best.PricePerHourDERO*2 {
		t.Fatalf("Quote math wrong: %+v", q)
	}

	got, err := c.Connect("")
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if got.NodeID == "" {
		t.Fatal("Connect: empty quote node")
	}

	st, err := c.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.NodeID == "" {
		t.Fatalf("Status: no node after connect: %+v", st)
	}

	d, err := c.Diagnostics()
	if err != nil {
		t.Fatalf("Diagnostics: %v", err)
	}
	if len(d.Checks) == 0 {
		t.Fatal("Diagnostics: no checks")
	}

	if err := c.Disconnect(); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	st, err = c.Status()
	if err != nil {
		t.Fatalf("Status after disconnect: %v", err)
	}
	if st.Connected {
		t.Fatal("Status: still connected after disconnect")
	}
}

func TestConformanceFakes(t *testing.T) {
	b := &fakeBackend{nodes: fakeNodes()}
	c, err := veilnet.New(veilnet.Config{Approve: func(q veilnet.Quote) bool { return true }}, b)
	if err != nil {
		t.Fatal(err)
	}
	runConformance(t, c)

	// Cheapest-price selection is deterministic.
	best, err := c.Select()
	if err != nil {
		t.Fatal(err)
	}
	if best.NodeID != "cheap" {
		t.Fatalf("Select = %q, want cheap", best.NodeID)
	}

	// Denied approval aborts the connect and never touches the backend.
	denied, err := veilnet.New(veilnet.Config{Approve: func(q veilnet.Quote) bool { return false }}, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := denied.Connect("cheap"); !errors.Is(err, veilnet.ErrApprovalDenied) {
		t.Fatalf("denied connect = %v, want ErrApprovalDenied", err)
	}

	// Unknown node id is an error, not a connect.
	if _, err := c.Connect("nope"); err == nil {
		t.Fatal("Connect(unknown) must fail")
	}
}

func TestConformanceRealApp(t *testing.T) {
	a, err := app.NewDemo()
	if err != nil {
		t.Skipf("demo app unavailable: %v", err)
	}
	defer a.Close()
	c, err := veilnet.New(
		veilnet.Config{Approve: func(q veilnet.Quote) bool { return true }},
		&veilnet.AppBackend{App: a},
	)
	if err != nil {
		t.Fatal(err)
	}
	runConformance(t, c)
}
