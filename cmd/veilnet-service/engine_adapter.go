// Package main hosts the privileged VeilNet service.
//
// The service wires the real WireGuard tunnel engine (internal/tunnel)
// into the app orchestrator via tunnelAdapter below, so Connect/Disconnect
// drive a genuine WireGuard data plane. If engine construction ever fails,
// the service refuses to start rather than serving a fake PROTECTED state.
package main

import (
	"golang.zx2c4.com/wireguard/conn"

	"github.com/dero-veilnet/veilnet/internal/app"
	"github.com/dero-veilnet/veilnet/internal/config"
	"github.com/dero-veilnet/veilnet/internal/transport"
	"github.com/dero-veilnet/veilnet/internal/tunnel"
)

// tunnelAdapter bridges tunnel.Engine (binding contract types) to the
// app.Engine interface (mirror types). Conversions are field-for-field;
// byte counters saturate at math.MaxInt64 on cast.
type tunnelAdapter struct{ e tunnel.Engine }

func toTunnelPeers(peers []app.Peer) []tunnel.Peer {
	out := make([]tunnel.Peer, 0, len(peers))
	for _, p := range peers {
		out = append(out, tunnel.Peer{
			PublicKey:  p.PublicKey,
			Endpoint:   p.Endpoint,
			AllowedIPs: append([]string(nil), p.AllowedIPs...),
			Keepalive:  p.Keepalive,
		})
	}
	return out
}

func toTunnelConfig(cfg app.WGConfig) tunnel.WireGuardConfig {
	return tunnel.WireGuardConfig{
		PrivateKey: cfg.PrivateKey,
		Addresses:  append([]string(nil), cfg.Addresses...),
		DNS:        append([]string(nil), cfg.DNS...),
		Peers:      toTunnelPeers(cfg.Peers),
	}
}

func (a tunnelAdapter) Start(cfg app.WGConfig) error { return a.e.Start(toTunnelConfig(cfg)) }

func (a tunnelAdapter) Stop() error { return a.e.Stop() }

func (a tunnelAdapter) Status() app.EngineStatus {
	st := a.e.Status()
	return app.EngineStatus{
		State:         string(st.State),
		Since:         st.Since,
		Endpoint:      st.Endpoint,
		LastHandshake: st.LastHandshake,
	}
}

func (a tunnelAdapter) Statistics() app.EngineStats {
	s := a.e.Statistics()
	return app.EngineStats{
		RxBytes:       saturate(s.RxBytes),
		TxBytes:       saturate(s.TxBytes),
		LastHandshake: s.LastHandshake,
	}
}

func (a tunnelAdapter) ApplyConfiguration(cfg app.WGConfig) error {
	return a.e.ApplyConfiguration(toTunnelConfig(cfg))
}

func (a tunnelAdapter) RotateEndpoint(endpoint string) error {
	return a.e.RotateEndpoint(endpoint)
}

func saturate(v uint64) int64 {
	const max = int64(^uint64(0) >> 1)
	if v > uint64(max) {
		return max
	}
	return int64(v)
}

// newEngine builds the production tunnel engine (userspace wireguard-go,
// kernel WireGuardNT path when the OS interface already exists).
//
// The configured entry transport supplies the UDP bind. An unregistered
// transport is a hard startup failure, never a quiet fall back to plain
// UDP: a client that believes it is bridged while sending plain UDP is
// worse than one that refuses to start.
func newEngine(cfg config.ClientConfig) (app.Engine, error) {
	tr, err := transport.Get(cfg.Network.Transport)
	if err != nil {
		return nil, err
	}
	opts := []tunnel.Option{}
	if tr.Name() != transport.DirectName {
		// endpoint is not known until Connect; transports needing it
		// read it from the peer config the engine applies.
		opts = append(opts, tunnel.WithBindFactory(func() (conn.Bind, error) {
			return tr.NewBind("")
		}))
	}
	return tunnelAdapter{e: tunnel.New(opts...)}, nil
}
