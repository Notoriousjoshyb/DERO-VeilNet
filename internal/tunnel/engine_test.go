// Loopback end-to-end test: two real wireguard-go userspace devices peered
// over 127.0.0.1 UDP, plumbed through in-memory TUNs. No admin rights, no
// OS interfaces, no mocks in the crypto path — handshake, encryption and
// counters are genuine.
package tunnel

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/dero-veilnet/veilnet/internal/events"
	vwg "github.com/dero-veilnet/veilnet/internal/wireguard"
)

// memTUN is an in-memory tun.Device: Read delivers packets injected via
// Inject (test -> device); Write collects packets from the device.
type memTUN struct {
	name    string
	mtu     int
	toDev   chan []byte
	fromDev chan []byte
	events  chan tun.Event
	once    sync.Once
	closed  chan struct{}
}

func newMemTUN(name string) *memTUN {
	return &memTUN{
		name:    name,
		mtu:     1420,
		toDev:   make(chan []byte, 64),
		fromDev: make(chan []byte, 64),
		events:  make(chan tun.Event, 4),
		closed:  make(chan struct{}),
	}
}

func (t *memTUN) File() *os.File { return nil }

func (t *memTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-t.toDev:
		if len(bufs) == 0 || len(sizes) == 0 {
			return 0, errors.New("memtun: no buffers")
		}
		if len(pkt) > len(bufs[0])-offset {
			return 0, errors.New("memtun: packet too large")
		}
		copy(bufs[0][offset:], pkt)
		sizes[0] = len(pkt)
		return 1, nil
	case <-t.closed:
		return 0, errors.New("memtun: closed")
	}
}

func (t *memTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		pkt := append([]byte(nil), b[offset:]...)
		select {
		case t.fromDev <- pkt:
		case <-t.closed:
			return 0, errors.New("memtun: closed")
		}
	}
	return len(bufs), nil
}

func (t *memTUN) MTU() (int, error)        { return t.mtu, nil }
func (t *memTUN) Name() (string, error)    { return t.name, nil }
func (t *memTUN) Events() <-chan tun.Event { return t.events }
func (t *memTUN) BatchSize() int           { return 1 }

func (t *memTUN) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}

// Inject delivers a plaintext IP packet into the device.
func (t *memTUN) Inject(pkt []byte) {
	select {
	case t.toDev <- append([]byte(nil), pkt...):
	case <-t.closed:
	}
}

// Next collects one decrypted packet from the device (with timeout).
func (t *memTUN) Next(timeout time.Duration) ([]byte, error) {
	select {
	case pkt := <-t.fromDev:
		return pkt, nil
	case <-time.After(timeout):
		return nil, errors.New("memtun: timeout waiting for packet")
	}
}

// ipv4UDP crafts a minimal IPv4/UDP packet (checksums: IP correct, UDP zero).
func ipv4UDP(src, dst net.IP, sport, dport int, payload []byte) []byte {
	hdr := make([]byte, 20)
	hdr[0] = 0x45
	total := 20 + 8 + len(payload)
	binary.BigEndian.PutUint16(hdr[2:], uint16(total))
	hdr[8] = 64
	hdr[9] = 17 // UDP
	copy(hdr[12:16], src.To4())
	copy(hdr[16:20], dst.To4())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(hdr[10:], ^uint16(sum))
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], uint16(sport))
	binary.BigEndian.PutUint16(udp[2:], uint16(dport))
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	return append(append(hdr, udp...), payload...)
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(port)
	return n
}

func waitState(t *testing.T, e Engine, want State, timeout time.Duration) Status {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st := e.Status()
		if st.State == want {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
	st := e.Status()
	t.Fatalf("state = %s (%+v), want %s", st.State, st, want)
	return st
}

func TestEngineLoopbackCycle(t *testing.T) {
	privA, pubA, err := vwg.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	privB, pubB, err := vwg.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	portA, portB := freeUDPPort(t), freeUDPPort(t)
	epA := "127.0.0.1:" + strconv.Itoa(portA)
	epB := "127.0.0.1:" + strconv.Itoa(portB)

	tunA, tunB := newMemTUN("test-a"), newMemTUN("test-b")
	engA := New(
		WithInterfaceName("veiltest-a"), WithListenPort(portA),
		WithTUNFactory(func(string, int) (tun.Device, error) { return tunA, nil }),
		WithBindFactory(StdNetBindFactory),
		WithPollInterval(100*time.Millisecond),
	)
	engB := New(
		WithInterfaceName("veiltest-b"), WithListenPort(portB),
		WithTUNFactory(func(string, int) (tun.Device, error) { return tunB, nil }),
		WithBindFactory(StdNetBindFactory),
		WithPollInterval(100*time.Millisecond),
	)

	started := make(chan any, 4)
	events.Subscribe(events.TUNNEL_STARTED, started)
	stopped := make(chan any, 4)
	events.Subscribe(events.TUNNEL_STOPPED, stopped)

	cfgA := WireGuardConfig{
		PrivateKey: privA, Addresses: []string{"10.7.0.1/32"},
		Peers: []Peer{{PublicKey: pubB, Endpoint: epB,
			AllowedIPs: []string{"10.7.0.2/32"}, Keepalive: 1}},
	}
	cfgB := WireGuardConfig{
		PrivateKey: privB, Addresses: []string{"10.7.0.2/32"},
		Peers: []Peer{{PublicKey: pubA, Endpoint: epA,
			AllowedIPs: []string{"10.7.0.1/32"}, Keepalive: 1}},
	}
	if err := engA.Start(cfgA); err != nil {
		t.Fatalf("start A: %v", err)
	}
	if err := engB.Start(cfgB); err != nil {
		t.Fatalf("start B: %v", err)
	}

	// Trigger the real handshake with genuine tunnel traffic.
	ipA, ipB := net.ParseIP("10.7.0.1"), net.ParseIP("10.7.0.2")
	tunA.Inject(ipv4UDP(ipA, ipB, 40001, 40002, []byte("ping-a")))

	// Both sides must reach UP from a real handshake — never asserted blindly.
	waitState(t, engA, UP, 15*time.Second)
	waitState(t, engB, UP, 15*time.Second)

	// Round trip through real encryption.
	got, err := tunB.Next(10 * time.Second)
	if err != nil {
		t.Fatalf("B received nothing: %v", err)
	}
	if string(got[len(got)-6:]) != "ping-a" {
		t.Fatalf("B got corrupt payload %q", got)
	}
	tunB.Inject(ipv4UDP(ipB, ipA, 40002, 40001, []byte("pong-b")))
	got, err = tunA.Next(10 * time.Second)
	if err != nil {
		t.Fatalf("A received nothing: %v", err)
	}
	if string(got[len(got)-6:]) != "pong-b" {
		t.Fatalf("A got corrupt payload %q", got)
	}

	// Statistics are real and monotonic (keepalives keep flowing).
	s1 := engA.Statistics()
	if s1.RxBytes == 0 || s1.TxBytes == 0 {
		t.Fatalf("expected live counters, got %+v", s1)
	}
	if s1.LastHandshake.IsZero() {
		t.Fatal("expected real handshake timestamp")
	}
	time.Sleep(2200 * time.Millisecond)
	s2 := engA.Statistics()
	if s2.TxBytes < s1.TxBytes || s2.RxBytes < s1.RxBytes {
		t.Fatalf("counters regressed: %+v -> %+v", s1, s2)
	}
	if s2.TxBytes+s2.RxBytes <= s1.TxBytes+s1.RxBytes {
		t.Fatalf("expected keepalive growth: %+v -> %+v", s1, s2)
	}

	// RotateEndpoint to the same peer is a legal no-op-ish rebind.
	if err := engA.RotateEndpoint(epB); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if st := engA.Status(); st.Endpoint != epB {
		t.Fatalf("endpoint = %q, want %q", st.Endpoint, epB)
	}

	if err := engA.Stop(); err != nil {
		t.Fatalf("stop A: %v", err)
	}
	if err := engB.Stop(); err != nil {
		t.Fatalf("stop B: %v", err)
	}
	if st := engA.Status(); st.State != DOWN {
		t.Fatalf("A state = %s, want DOWN", st.State)
	}
	if st := engB.Status(); st.State != DOWN {
		t.Fatalf("B state = %s, want DOWN", st.State)
	}
	if err := engA.Stop(); err != nil {
		t.Fatalf("second stop should be idempotent: %v", err)
	}

	select {
	case <-started:
	default:
		t.Fatal("missing TUNNEL_STARTED event")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("missing TUNNEL_STOPPED event")
	}
}

func TestBackoffBounds(t *testing.T) {
	if backoffFor(1) != time.Second {
		t.Fatalf("base = %v", backoffFor(1))
	}
	prev := backoffFor(1)
	for i := 2; i <= 10; i++ {
		d := backoffFor(i)
		if d < prev {
			t.Fatalf("backoff not monotonic at %d: %v < %v", i, d, prev)
		}
		prev = d
	}
	if got := backoffFor(100); got != time.Minute {
		t.Fatalf("cap = %v, want 1m", got)
	}
}

func TestStartValidation(t *testing.T) {
	e := New(WithPollInterval(time.Hour))
	if err := e.Start(WireGuardConfig{}); err == nil {
		t.Fatal("empty config must fail")
	}
	if st := e.Status(); st.State != DOWN {
		t.Fatalf("failed start must stay DOWN, got %s", st.State)
	}
}
