package nodes

import (
	"context"
	"time"
)

// Heartbeat is the liveness payload published to the registry.
type Heartbeat struct {
	NodeID          string  `json:"node_id"`
	Version         string  `json:"version"`
	ProtocolVersion int     `json:"protocol_version"`
	Load            float64 `json:"load"`
	Clients         int     `json:"clients"`
	MaxClients      int     `json:"max_clients"`
	UptimeSec       int64   `json:"uptime_sec"`
	Region          string  `json:"region"`
	NodeType        string  `json:"node_type"`
}

// BuildHeartbeat snapshots the current liveness payload.
func (c *Controller) BuildHeartbeat() Heartbeat {
	c.mu.Lock()
	region := c.cfg.Region
	nt := string(c.cfg.NodeType)
	max := c.cfg.MaxClients
	id := c.cfg.NodeID
	c.mu.Unlock()
	return Heartbeat{
		NodeID:          id,
		Version:         Version,
		ProtocolVersion: ProtocolVersion,
		Load:            c.Load(),
		Clients:         c.ses.ActiveCount(),
		MaxClients:      max,
		UptimeSec:       int64(c.Uptime().Seconds()),
		Region:          region,
		NodeType:        nt,
	}
}

// StartHeartbeatLoop publishes heartbeats until ctx ends. A nil client
// keeps the loop alive as a local event tick (NODE_HEARTBEAT).
func (c *Controller) StartHeartbeatLoop(ctx context.Context, interval time.Duration, client RegistryClient) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if client == nil {
		client = NullRegistry{}
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				hb := c.BuildHeartbeat()
				_ = client.PublishHeartbeat(hb)
				c.emit("NODE_HEARTBEAT", hb)
			}
		}
	}()
}

// StartSweeper evicts expired sessions on a tick until ctx ends.
func (c *Controller) StartSweeper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c.SweepOnce(time.Now())
			}
		}
	}()
}
