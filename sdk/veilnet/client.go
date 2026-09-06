package veilnet

import (
	"errors"
	"fmt"
	"sort"
)

// Node is one candidate exit/relay node (app/registry-shaped, local).
type Node struct {
	NodeID           string  `json:"node_id"`
	Region           string  `json:"region"`
	Country          string  `json:"country"`
	Endpoint         string  `json:"endpoint"`
	PricePerHourDERO float64 `json:"price_per_hour_dero"`
	LatencyMs        int64   `json:"latency_ms"` // -1 unknown
	BondDERO         float64 `json:"bond_dero"`
	Trust            float64 `json:"trust"` // local 0..1
	Status           string  `json:"status"`
}

// Quote prices hours on a node. AmountDERO is informational: spending it
// still requires the explicit ApproveHook/ConfirmPayment path.
type Quote struct {
	NodeID     string  `json:"node_id"`
	Hours      float64 `json:"hours"`
	AmountDERO float64 `json:"amount_dero"`
}

// Status is the observable connection state.
type Status struct {
	Connected   bool   `json:"connected"`
	EngineState string `json:"engine_state"`
	NodeID      string `json:"node_id,omitempty"`
	Endpoint    string `json:"endpoint,omitempty"`
	ElapsedSecs int64  `json:"elapsed_secs"`
	Demo        bool   `json:"demo"`
}

// Diagnostics is a privacy/health snapshot. All fields are observed
// values; "unknown" means unknown, never fabricated.
type Diagnostics struct {
	Connected   bool            `json:"connected"`
	EngineState string          `json:"engine_state"`
	NodeID      string          `json:"node_id,omitempty"`
	Checks      map[string]string `json:"checks,omitempty"`
}

// Discovery lists candidate nodes (app ListNodes / registry shaped).
type Discovery interface {
	ListNodes() ([]Node, error)
}

// Connector drives the tunnel (app Connect/Disconnect shaped).
type Connector interface {
	Connect(nodeID string) error
	Disconnect() error
}

// Observer reads state and diagnostics (app State/Diagnose shaped).
type Observer interface {
	Observe() (Status, error)
	Diagnose() (Diagnostics, error)
}

// Backend bundles the three roles; adapters and fakes implement it.
type Backend interface {
	Discovery
	Connector
	Observer
}

// ApproveHook authorizes one priced quote. Returning false aborts the
// connect with ErrApprovalDenied. Nil hook denies all paid connects and
// allows only free (price 0) nodes — VeilNet never auto-spends.
type ApproveHook func(q Quote) bool

// ErrApprovalDenied means the payment hook declined the quote.
var ErrApprovalDenied = errors.New("veilnet: payment approval denied")

// Config tunes the Client. Zero value is usable: no region filter,
// no price cap, 1-hour quotes.
type Config struct {
	Region            string
	MaxPricePerHour   float64 // >0 excludes pricier nodes
	QuoteHours        float64 // <=0 defaults to 1
	Approve           ApproveHook
}

// Client is the SDK entry point. It is safe for concurrent use.
type Client struct {
	cfg     Config
	backend Backend
}

// New builds a Client over b. b must be non-nil.
func New(cfg Config, b Backend) (*Client, error) {
	if b == nil {
		return nil, errors.New("veilnet: nil backend")
	}
	if cfg.QuoteHours <= 0 {
		cfg.QuoteHours = 1
	}
	return &Client{cfg: cfg, backend: b}, nil
}

// Discover returns all candidate nodes from the backend.
func (c *Client) Discover() ([]Node, error) {
	nodes, err := c.backend.ListNodes()
	if err != nil {
		return nil, fmt.Errorf("veilnet: discover: %w", err)
	}
	return nodes, nil
}

// filter applies region/price/status filters, dropping unavailable nodes.
func (c *Client) filter(nodes []Node) []Node {
	var out []Node
	for _, n := range nodes {
		if n.Status != "" && n.Status != "active" {
			continue
		}
		if c.cfg.Region != "" && n.Region != c.cfg.Region {
			continue
		}
		if c.cfg.MaxPricePerHour > 0 && n.PricePerHourDERO > c.cfg.MaxPricePerHour {
			continue
		}
		out = append(out, n)
	}
	return out
}

// Select returns the best node: lowest price, then lowest known latency,
// then lexicographically smaller id (deterministic).
func (c *Client) Select() (Node, error) {
	nodes, err := c.Discover()
	if err != nil {
		return Node{}, err
	}
	cands := c.filter(nodes)
	if len(cands) == 0 {
		return Node{}, errors.New("veilnet: no suitable node")
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].PricePerHourDERO != cands[j].PricePerHourDERO {
			return cands[i].PricePerHourDERO < cands[j].PricePerHourDERO
		}
		li, lj := cands[i].LatencyMs, cands[j].LatencyMs
		if li < 0 {
			li = 1<<62 - 1
		}
		if lj < 0 {
			lj = 1<<62 - 1
		}
		if li != lj {
			return li < lj
		}
		return cands[i].NodeID < cands[j].NodeID
	})
	return cands[0], nil
}

// Quote prices hours on the node (hours <= 0 uses Config.QuoteHours).
func (c *Client) Quote(n Node, hours float64) Quote {
	if hours <= 0 {
		hours = c.cfg.QuoteHours
	}
	return Quote{NodeID: n.NodeID, Hours: hours, AmountDERO: n.PricePerHourDERO * hours}
}

// Connect selects (when nodeID == "") or resolves the node, prices it,
// runs the approval hook for any non-zero amount, then connects.
// Nothing is spent here: settlement stays on the explicit payments path.
func (c *Client) Connect(nodeID string) (Quote, error) {
	var node Node
	if nodeID == "" {
		best, err := c.Select()
		if err != nil {
			return Quote{}, err
		}
		node = best
	} else {
		nodes, err := c.Discover()
		if err != nil {
			return Quote{}, err
		}
		found := false
		for _, n := range nodes {
			if n.NodeID == nodeID {
				node, found = n, true
				break
			}
		}
		if !found {
			return Quote{}, fmt.Errorf("veilnet: unknown node %q", nodeID)
		}
	}
	q := c.Quote(node, 0)
	if q.AmountDERO > 0 {
		if c.cfg.Approve == nil || !c.cfg.Approve(q) {
			return q, ErrApprovalDenied
		}
	}
	if err := c.backend.Connect(node.NodeID); err != nil {
		return q, fmt.Errorf("veilnet: connect: %w", err)
	}
	return q, nil
}

// Status snapshots connection state.
func (c *Client) Status() (Status, error) {
	st, err := c.backend.Observe()
	if err != nil {
		return Status{}, fmt.Errorf("veilnet: status: %w", err)
	}
	return st, nil
}

// Diagnostics snapshots privacy/health posture.
func (c *Client) Diagnostics() (Diagnostics, error) {
	d, err := c.backend.Diagnose()
	if err != nil {
		return Diagnostics{}, fmt.Errorf("veilnet: diagnostics: %w", err)
	}
	return d, nil
}

// Disconnect stops the tunnel.
func (c *Client) Disconnect() error {
	if err := c.backend.Disconnect(); err != nil {
		return fmt.Errorf("veilnet: disconnect: %w", err)
	}
	return nil
}
