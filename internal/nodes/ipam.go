package nodes

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
)

// IPAM hands out per-client /32 addresses from the CGNAT /10 range
// (default 100.64.0.0/10). The server address (.0.1) and the network
// address are never handed out.
type IPAM struct {
	mu      sync.Mutex
	network *net.IPNet
	base    uint32
	size    uint32
	next    uint32
	used    map[uint32]bool

	serverIP string
}

// NewIPAM creates an allocator over cidr (e.g. "100.64.0.0/10").
func NewIPAM(cidr string) (*IPAM, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("nodes: bad cgnat cidr: %w", err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, errors.New("nodes: cgnat must be IPv4")
	}
	mask := binary.BigEndian.Uint32(network.Mask)
	base := binary.BigEndian.Uint32(ip4.Mask(network.Mask))
	size := ^mask + 1
	if size < 8 {
		return nil, errors.New("nodes: cgnat range too small")
	}
	server := make(net.IP, 4)
	binary.BigEndian.PutUint32(server, base+1)
	return &IPAM{
		network:  network,
		base:     base,
		size:     size,
		next:     2, // .0 = net, .1 = server
		used:     make(map[uint32]bool),
		serverIP: server.String(),
	}, nil
}

// ServerIP returns the gateway address handed to the WireGuard device.
func (a *IPAM) ServerIP() string { return a.serverIP }

// Allocate returns the next free client address (bare IP, no mask).
func (a *IPAM) Allocate() (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := uint32(0); i < a.size-2; i++ {
		off := a.next
		a.next++
		if a.next >= a.size-1 {
			a.next = 2
		}
		if a.used[off] {
			continue
		}
		// Skip broadcast.
		if off == a.size-1 {
			continue
		}
		a.used[off] = true
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, a.base+off)
		return ip.String(), nil
	}
	return "", errors.New("nodes: address pool exhausted")
}

// Release frees an address.
func (a *IPAM) Release(ipStr string) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return
	}
	off := binary.BigEndian.Uint32(ip) - a.base
	a.mu.Lock()
	delete(a.used, off)
	a.mu.Unlock()
}

// Reserve marks an address in use (restore from sqlite on startup).
func (a *IPAM) Reserve(ipStr string) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return
	}
	off := binary.BigEndian.Uint32(ip) - a.base
	if off < 2 || off >= a.size-1 {
		return
	}
	a.mu.Lock()
	a.used[off] = true
	a.mu.Unlock()
}

// Used returns the leased count.
func (a *IPAM) Used() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.used)
}
