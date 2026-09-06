package app

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dero-veilnet/veilnet/internal/config"
	"github.com/dero-veilnet/veilnet/internal/storage"
)

// Demo seeds. Clearly badged in the UI; demo state never touches prod files
// (in-memory store, loopback endpoints, fixed fake keys).
var demoNodes = []NodeInfo{
	// NOTE: distinct loopback hosts on purpose — the multihop builder
	// rejects hops sharing one machine (same-box rule).
	{NodeID: "demo-eu-01", WGPubkey: "DEMOdemodEModemoDemoDEMOdemoDEMOdemoDEMOdemo00=", Region: "eu-west", Country: "DE", City: "Frankfurt", Endpoint: "127.0.0.1:51821", PricePerHourDero: 0.05, CapacityMaxClients: 100, ProtocolVersion: 1, BondDero: 50, Status: "active", Version: "demo-1", Load: 0.3},
	{NodeID: "demo-us-01", WGPubkey: "DEMOdemodEModemoDemoDEMOdemoDEMOdemoDEMOdemo11=", Region: "us-east", Country: "US", City: "New York", Endpoint: "127.0.0.2:51822", PricePerHourDero: 0.03, CapacityMaxClients: 200, ProtocolVersion: 1, BondDero: 100, Status: "active", Version: "demo-1", Load: 0.6},
	{NodeID: "demo-ap-01", WGPubkey: "DEMOdemodEModemoDemoDEMOdemoDEMOdemoDEMOdemo22=", Region: "ap-south", Country: "SG", City: "Singapore", Endpoint: "127.0.0.3:51823", PricePerHourDero: 0.08, CapacityMaxClients: 50, ProtocolVersion: 1, BondDero: 25, Status: "active", Version: "demo-1", Load: 0.15},
}

// NewDemo builds an isolated demo App: seeded fake nodes, in-memory store,
// fake engine. Never mixes with prod state.
func NewDemo() (*App, error) {
	cfg := config.DefaultClientConfig()
	cfg.Region = "eu-west"
	store, err := storage.Open(":memory:")
	if err != nil {
		return nil, err
	}
	a := New(cfg, store, NewFakeEngine(), NewStaticNodes(append([]NodeInfo(nil), demoNodes...)))
	a.demo = true
	if home, herr := os.UserHomeDir(); herr == nil {
		a.savePath = filepath.Join(home, ".veilnet", "demo-config.toml")
	}
	for _, n := range demoNodes {
		_ = store.SaveNode(storage.Node{
			NodeID: n.NodeID, WGPubkey: n.WGPubkey, Region: n.Region,
			Country: n.Country, City: n.City, Endpoint: n.Endpoint,
			PricePerHourDero: n.PricePerHourDero, CapacityMaxClients: n.CapacityMaxClients,
			ProtocolVersion: n.ProtocolVersion, BondDero: n.BondDero,
			Status: n.Status, Version: n.Version, LastSeen: time.Now(),
		})
		_ = store.SetTrust(n.NodeID, 0.8, 10)
	}
	return a, nil
}

// FakeEngine is an in-process Engine for demo/tests. It performs real state
// transitions (DOWN->CONNECTING->UP) with live timers and byte counters;
// demo stats are honestly labeled by the DEMO badge, never prod traffic.
type FakeEngine struct {
	mu       sync.Mutex
	state    string
	since    time.Time
	endpoint string
	hs       time.Time
	rx, tx   int64
}

// NewFakeEngine returns a DOWN engine.
func NewFakeEngine() *FakeEngine {
	return &FakeEngine{state: StateDown, since: time.Now()}
}

// Start transitions CONNECTING->UP after a short handshake delay.
func (f *FakeEngine) Start(cfg WGConfig) error {
	f.mu.Lock()
	if len(cfg.Peers) == 0 {
		f.mu.Unlock()
		return errNoPeer
	}
	f.state = StateConnecting
	f.since = time.Now()
	f.endpoint = cfg.Peers[0].Endpoint
	f.mu.Unlock()
	go func() {
		time.Sleep(400 * time.Millisecond)
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.state == StateConnecting {
			f.state = StateUp
			f.hs = time.Now()
		}
	}()
	return nil
}

// Stop returns to DOWN.
func (f *FakeEngine) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = StateDown
	f.since = time.Now()
	return nil
}

// Status reports current state.
func (f *FakeEngine) Status() EngineStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return EngineStatus{State: f.state, Since: f.since, Endpoint: f.endpoint, LastHandshake: f.hs}
}

// Statistics returns live counters (ticking while UP).
func (f *FakeEngine) Statistics() EngineStats {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state == StateUp {
		secs := time.Since(f.hs).Seconds()
		if secs < 0 {
			secs = 0
		}
		f.rx = int64(secs * 128 * 1024)
		f.tx = int64(secs * 32 * 1024)
	}
	return EngineStats{RxBytes: f.rx, TxBytes: f.tx, LastHandshake: f.hs}
}

// ApplyConfiguration swaps the endpoint.
func (f *FakeEngine) ApplyConfiguration(cfg WGConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(cfg.Peers) == 0 {
		return errNoPeer
	}
	f.endpoint = cfg.Peers[0].Endpoint
	return nil
}

// RotateEndpoint moves to a new endpoint and re-handshakes.
func (f *FakeEngine) RotateEndpoint(endpoint string) error {
	f.mu.Lock()
	f.endpoint = endpoint
	f.state = StateConnecting
	f.mu.Unlock()
	go func() {
		time.Sleep(300 * time.Millisecond)
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.state == StateConnecting {
			f.state = StateUp
			f.hs = time.Now()
		}
	}()
	return nil
}

var errNoPeer = errorString("no peers in configuration")

type errorString string

func (e errorString) Error() string { return string(e) }
