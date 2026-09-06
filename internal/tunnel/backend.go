// Backend selection and implementations for the tunnel engine.
//
// userspaceBackend embeds a wireguard-go device over a TUN interface:
//   - production: tun.CreateTUN (Wintun on Windows, utun/getifaddrs
//     elsewhere) + conn.NewDefaultBind.
//   - tests: injected in-memory TUN + loopback UDP binds.
//
// kernelBackend configures a pre-existing OS interface (created by the
// WireGuardNT service path, documented in docs/WINDOWS_NETWORKING.md) via
// wgctrl. It is selected when the interface already exists; otherwise Start
// falls through to userspace.
package tunnel

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	wgctrl "golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	vwg "github.com/dero-veilnet/veilnet/internal/wireguard"
)

// TUNFactory creates the TUN interface for the userspace backend.
type TUNFactory func(name string, mtu int) (tun.Device, error)

// BindFactory creates the UDP bind for the userspace backend.
type BindFactory func() (conn.Bind, error)

// backend is the live data-plane handle owned by the engine.
type backend interface {
	// probe scrapes rx/tx counters and newest handshake from the device.
	probe() (rx, tx uint64, lastHandshake time.Time, err error)
	// apply replaces the peer/endpoint configuration.
	apply(cfg WireGuardConfig) error
	// rebind refreshes the UDP socket (NAT / sleep-wake recovery).
	rebind() error
	// close tears the backend down.
	close() error
}

// errNoKernelIface signals fallback from kernel to userspace backend.
var errNoKernelIface = errors.New("tunnel: no pre-existing interface, using userspace")

func defaultTUNFactory(name string, mtu int) (tun.Device, error) {
	return tun.CreateTUN(name, mtu)
}
func defaultBindFactory() (conn.Bind, error) {
	return conn.NewDefaultBind(), nil
}

// StdNetBindFactory builds classic userspace UDP binds (no WinRing RIO).
// Used by tests where RIO loopback delivery is unavailable; production
// keeps NewDefaultBind.
func StdNetBindFactory() (conn.Bind, error) {
	return conn.NewStdNetBind(), nil
}

// createBackend selects the data-plane backend: kernel first (when the
// OS probe reports it usable and the interface exists), userspace
// otherwise. The decision is always logged and recorded for
// Status().Detail — never silent, never faked.
func (e *engine) createBackend(cfg WireGuardConfig) (backend, error) {
	avail, detail := probeKernel()
	log.Printf("tunnel: kernel probe for %q: available=%v (%s)", e.iface, avail, detail)
	if avail {
		if kb, err := openKernel(e.iface, cfg, e.listenPort); err == nil {
			log.Printf("tunnel: using kernel backend for %q (%s)", e.iface, detail)
			e.backendKind, e.backendDetail = BackendKernel, detail
			return kb, nil
		} else if !errors.Is(err, errNoKernelIface) {
			// A real kernel-path failure (permissions, driver) is worth
			// surfacing, but userspace may still work — try it.
			log.Printf("tunnel: kernel backend failed (%v); trying userspace", err)
			if ub, uerr := e.openUserspace(cfg); uerr == nil {
				rep := "kernel failed (" + err.Error() + "); " + detail
				e.backendKind, e.backendDetail = BackendUserspace, rep
				log.Printf("tunnel: using userspace backend for %q (%s)", e.iface, rep)
				return ub, nil
			}
			return nil, err
		}
		log.Printf("tunnel: no pre-existing interface %q; using userspace", e.iface)
	}
	ub, uerr := e.openUserspace(cfg)
	if uerr != nil {
		return nil, uerr
	}
	rep := detail
	if rep == "" {
		rep = "kernel unavailable"
	}
	e.backendKind, e.backendDetail = BackendUserspace, rep
	log.Printf("tunnel: using userspace backend for %q (%s)", e.iface, rep)
	return ub, nil
}

// ---------------------------------------------------------------------------
// userspace backend (wireguard-go)
// ---------------------------------------------------------------------------

type userspaceBackend struct {
	dev    *device.Device
	tunDev tun.Device
}

func (e *engine) openUserspace(cfg WireGuardConfig) (backend, error) {
	mtu := vwg.Config{}.MTUOrDefault()
	tunDev, err := e.newTUN(e.iface, mtu)
	if err != nil {
		return nil, fmt.Errorf("tunnel: create TUN: %w", err)
	}
	bind, err := e.newBind()
	if err != nil {
		_ = tunDev.Close()
		return nil, fmt.Errorf("tunnel: create bind: %w", err)
	}
	logger := device.NewLogger(device.LogLevelSilent, "[veilnet] ")
	dev := device.NewDevice(tunDev, bind, logger)
	wcfg := toWireguard(cfg, e.listenPort)
	ipc, err := vwg.ToIPC(wcfg)
	if err != nil {
		dev.Close()
		_ = tunDev.Close()
		return nil, err
	}
	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		_ = tunDev.Close()
		return nil, fmt.Errorf("tunnel: apply IPC config: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		_ = tunDev.Close()
		return nil, fmt.Errorf("tunnel: device up: %w", err)
	}
	return &userspaceBackend{dev: dev, tunDev: tunDev}, nil
}

func (b *userspaceBackend) probe() (uint64, uint64, time.Time, error) {
	dump, err := b.dev.IpcGet()
	if err != nil {
		return 0, 0, time.Time{}, err
	}
	rx, tx, hs := vwg.AggregateStats(vwg.ParseIPCDump(dump))
	return rx, tx, hs, nil
}

func (b *userspaceBackend) apply(cfg WireGuardConfig) error {
	ipc, err := vwg.ToIPC(toWireguard(cfg, 0))
	if err != nil {
		return err
	}
	return b.dev.IpcSet(ipc)
}

func (b *userspaceBackend) rebind() error {
	return b.dev.BindUpdate()
}

func (b *userspaceBackend) close() error {
	b.dev.Close()
	return b.tunDev.Close()
}

// ---------------------------------------------------------------------------
// kernel backend (wgctrl over a pre-existing interface)
// ---------------------------------------------------------------------------

type kernelBackend struct {
	client *wgctrl.Client
	iface  string
}

func openKernel(iface string, cfg WireGuardConfig, listenPort int) (backend, error) {
	client, err := wgctrl.New()
	if err != nil {
		// Cannot even talk to the platform API: let userspace try.
		return nil, errNoKernelIface
	}
	if _, err := client.Device(iface); err != nil {
		_ = client.Close()
		return nil, errNoKernelIface
	}
	be := &kernelBackend{client: client, iface: iface}
	if err := be.apply(cfg); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("tunnel: configure %s: %w", iface, err)
	}
	_ = listenPort
	return be, nil
}

func (b *kernelBackend) probe() (uint64, uint64, time.Time, error) {
	d, err := b.client.Device(b.iface)
	if err != nil {
		return 0, 0, time.Time{}, err
	}
	var rx, tx int64
	var hs time.Time
	for _, p := range d.Peers {
		rx += p.ReceiveBytes
		tx += p.TransmitBytes
		if p.LastHandshakeTime.After(hs) {
			hs = p.LastHandshakeTime
		}
	}
	if rx < 0 {
		rx = 0
	}
	if tx < 0 {
		tx = 0
	}
	return uint64(rx), uint64(tx), hs, nil
}

func (b *kernelBackend) rebind() error {
	// No portable rebind primitive: re-resolve endpoints by re-applying
	// the current device config with UpdateOnly peers.
	d, err := b.client.Device(b.iface)
	if err != nil {
		return err
	}
	peers := make([]wgtypes.PeerConfig, 0, len(d.Peers))
	for _, p := range d.Peers {
		ka := p.PersistentKeepaliveInterval
		peers = append(peers, wgtypes.PeerConfig{
			PublicKey:                   p.PublicKey,
			UpdateOnly:                  true,
			Endpoint:                    p.Endpoint,
			PersistentKeepaliveInterval: &ka,
		})
	}
	return b.client.ConfigureDevice(b.iface, wgtypes.Config{
		ReplacePeers: false,
		Peers:        peers,
	})
}

func (b *kernelBackend) close() error {
	// Leave the interface in place (it is OS-owned) but remove our peers
	// so no traffic keeps flowing after Stop.
	_ = b.client.ConfigureDevice(b.iface, wgtypes.Config{ReplacePeers: true})
	return b.client.Close()
}
func (b *kernelBackend) apply(cfg WireGuardConfig) error {
	wcfg, err := kernelConfig(cfg)
	if err != nil {
		return err
	}
	return b.client.ConfigureDevice(b.iface, wcfg)
}

// kernelConfig converts our config to a full-replace wgtypes.Config.
func kernelConfig(cfg WireGuardConfig) (wgtypes.Config, error) {
	priv, err := wgtypes.ParseKey(cfg.PrivateKey)
	if err != nil {
		return wgtypes.Config{}, fmt.Errorf("tunnel: bad private key: %w", err)
	}
	out := wgtypes.Config{PrivateKey: &priv, ReplacePeers: true}
	for i := range cfg.Peers {
		p := &cfg.Peers[i]
		pub, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return wgtypes.Config{}, fmt.Errorf("tunnel: peer %d bad key: %w", i, err)
		}
		pc := wgtypes.PeerConfig{PublicKey: pub, ReplaceAllowedIPs: true}
		if ep := p.Endpoint; ep != "" {
			udp, err := net.ResolveUDPAddr("udp", ep)
			if err != nil {
				return wgtypes.Config{}, fmt.Errorf("tunnel: peer %d bad endpoint: %w", i, err)
			}
			pc.Endpoint = udp
		}
		for _, a := range p.AllowedIPs {
			pfx, err := netip.ParsePrefix(a)
			if err != nil {
				return wgtypes.Config{}, fmt.Errorf("tunnel: peer %d bad allowed_ip: %w", i, err)
			}
			pc.AllowedIPs = append(pc.AllowedIPs, net.IPNet{
				IP:   pfx.Addr().AsSlice(),
				Mask: net.CIDRMask(pfx.Bits(), pfx.Addr().BitLen()),
			})
		}
		if p.Keepalive > 0 {
			ka := time.Duration(p.Keepalive) * time.Second
			pc.PersistentKeepaliveInterval = &ka
		}
		out.Peers = append(out.Peers, pc)
	}
	return out, nil
}
