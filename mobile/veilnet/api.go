package veilnet

import (
	"encoding/json"
	"strings"
)

// Version is the library version string.
const Version = "0.1.0"

// GetVersion returns the library version (plain string, no JSON).
func GetVersion() string { return Version }

// Configure applies a JSON mobileConfig and resets the client so the
// next call picks it up. Unknown fields are rejected. Returns an
// envelope (data = applied config JSON).
func Configure(configJSON string) string {
	var cfg mobileConfig
	dec := json.NewDecoder(strings.NewReader(configJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return fail("bad config: " + err.Error())
	}
	if cfg.QuoteHours < 0 {
		return fail("quote_hours must be >= 0")
	}
	if cfg.MaxPricePerHour < 0 {
		return fail("max_price_per_hour must be >= 0")
	}
	state.Lock()
	defer state.Unlock()
	if cfg.QuoteHours == 0 {
		cfg.QuoteHours = 1
	}
	state.config = cfg
	state.client = nil
	return ok(cfg)
}

// SelectNode returns the best node JSON for region ("" = configured
// default). Envelope data is an SDK Node object. A region with no nodes
// is a clear error, never a silent mismatch.
func SelectNode(region string) string {
	state.Lock()
	defer state.Unlock()
	if err := ensureClientLocked(); err != nil {
		return fail(err.Error())
	}
	if region == "" {
		best, err := state.client.Select()
		if err != nil {
			return fail(err.Error())
		}
		return ok(best)
	}
	nodes, err := state.client.Discover()
	if err != nil {
		return fail(err.Error())
	}
	found := false
	var cheapest float64
	var bestAny any
	for _, n := range nodes {
		if n.Region != region {
			continue
		}
		if n.Status != "" && n.Status != "active" {
			continue
		}
		if !found || n.PricePerHourDERO < cheapest {
			found = true
			cheapest = n.PricePerHourDERO
			bestAny = n
		}
	}
	if !found {
		return fail("no suitable node in region " + region)
	}
	return ok(bestAny)
}

// Start connects to nodeID ("" = auto-select). Envelope data is the
// approved Quote. Paid nodes require AllowPaid + caps from Configure;
// otherwise Start returns ok:false naming the fix.
//
// Start refuses unless the OS has handed over a tunnel (see
// permission.go): a mobile client must never report a connection it
// cannot actually carry. Demo mode is exempt because it carries no real
// traffic and is badged as demo.
func Start(nodeID string) string {
	state.Lock()
	defer state.Unlock()
	if err := ensureClientLocked(); err != nil {
		return fail(err.Error())
	}
	if err := requireTunnel(state.app != nil && state.app.IsDemo()); err != nil {
		return fail(err.Error())
	}
	q, err := state.client.Connect(nodeID)
	if err != nil {
		return fail(err.Error())
	}
	return ok(q)
}

// Stop disconnects. Idempotent: stopping while down is ok:true.
func Stop() string {
	state.Lock()
	defer state.Unlock()
	if err := ensureClientLocked(); err != nil {
		return fail(err.Error())
	}
	if err := state.client.Disconnect(); err != nil {
		return fail(err.Error())
	}
	return ok(map[string]string{"state": "down"})
}

// Status returns the connection Status JSON in the envelope.
func Status() string {
	state.Lock()
	defer state.Unlock()
	if err := ensureClientLocked(); err != nil {
		return fail(err.Error())
	}
	st, err := state.client.Status()
	if err != nil {
		return fail(err.Error())
	}
	return ok(st)
}

// Diagnostics returns the Diagnostics JSON in the envelope.
func Diagnostics() string {
	state.Lock()
	defer state.Unlock()
	if err := ensureClientLocked(); err != nil {
		return fail(err.Error())
	}
	d, err := state.client.Diagnostics()
	if err != nil {
		return fail(err.Error())
	}
	return ok(d)
}
