package veilnet

import (
	"github.com/dero-veilnet/veilnet/internal/app"
)

// AppBackend adapts the real *app.App to the Backend interface.
// It lives in its own file so client.go stays dependency-free.
type AppBackend struct {
	App *app.App
}

// ListNodes maps app NodeInfo to SDK Nodes.
func (b *AppBackend) ListNodes() ([]Node, error) {
	infos, err := b.App.ListNodes()
	if err != nil {
		return nil, err
	}
	out := make([]Node, 0, len(infos))
	for _, n := range infos {
		out = append(out, Node{
			NodeID:           n.NodeID,
			Region:           n.Region,
			Country:          n.Country,
			Endpoint:         n.Endpoint,
			PricePerHourDERO: n.PricePerHourDero,
			LatencyMs:        n.LatencyMs,
			BondDERO:         n.BondDero,
			Trust:            n.Trust,
			Status:           n.Status,
		})
	}
	return out, nil
}

// Connect delegates to app.Connect.
func (b *AppBackend) Connect(nodeID string) error { return b.App.Connect(nodeID) }

// Disconnect delegates to app.Disconnect.
func (b *AppBackend) Disconnect() error { return b.App.Disconnect() }

// Observe maps app ConnState to Status.
func (b *AppBackend) Observe() (Status, error) {
	st := b.App.State()
	s := Status{
		EngineState: st.EngineState,
		ElapsedSecs: st.ElapsedSecs,
		Demo:        st.Demo,
	}
	if st.Node != nil {
		s.NodeID = st.Node.NodeID
		s.Endpoint = st.Node.Endpoint
	}
	s.Connected = st.EngineState == app.StateUp
	return s, nil
}

func checkStr(c app.Check) string {
	if c.OK {
		return "ok:" + c.Value
	}
	return "fail:" + c.Value
}

// Diagnose maps app Diagnostics to the SDK shape.
func (b *AppBackend) Diagnose() (Diagnostics, error) {
	d := b.App.Diagnose()
	checks := map[string]string{
		"tunnel": checkStr(d.Tunnel),
		"exit":   checkStr(d.ExitIP),
		"dns":    checkStr(d.DNSRoute),
		"ipv6":   checkStr(d.IPv6),
		"kill":   checkStr(d.KillSwitch),
	}
	st := b.App.State()
	out := Diagnostics{
		EngineState: st.EngineState,
		Checks:      checks,
	}
	if st.Node != nil {
		out.NodeID = st.Node.NodeID
	}
	out.Connected = st.EngineState == app.StateUp
	return out, nil
}
