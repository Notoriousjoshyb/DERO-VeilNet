package ref

import "sync"

// Type mirrors the Contract event type.
type Type string

// Contract event names. The string values are binding.
const (
	NodeDiscovered   Type = "NODE_DISCOVERED"
	NodeConnected    Type = "NODE_CONNECTED"
	NodeDisconnected Type = "NODE_DISCONNECTED"
	TunnelStarted    Type = "TUNNEL_STARTED"
	TunnelStopped    Type = "TUNNEL_STOPPED"
	KillSwitchEnabled Type = "KILL_SWITCH_ENABLED"
	DNSChanged       Type = "DNS_CHANGED"
	PaymentRequested Type = "PAYMENT_REQUESTED"
	PaymentConfirmed Type = "PAYMENT_CONFIRMED"
	SessionAuthorized Type = "SESSION_AUTHORIZED"
	SessionExpired   Type = "SESSION_EXPIRED"
	NodeHeartbeat    Type = "NODE_HEARTBEAT"
	CircuitRotated   Type = "CIRCUIT_ROTATED"
	DeroConnected    Type = "DERO_CONNECTED"
	DeroDisconnected Type = "DERO_DISCONNECTED"
	ErrorEvent       Type = "ERROR"
)

// AllTypes lists every Contract event name for exhaustive assertions.
var AllTypes = []Type{
	NodeDiscovered, NodeConnected, NodeDisconnected,
	TunnelStarted, TunnelStopped, KillSwitchEnabled, DNSChanged,
	PaymentRequested, PaymentConfirmed, SessionAuthorized, SessionExpired,
	NodeHeartbeat, CircuitRotated, DeroConnected, DeroDisconnected,
	ErrorEvent,
}

// Bus is a synchronous in-memory event bus with the Contract shape:
// Publish(t, v); Subscribe(t, ch). Delivery is non-blocking with a drop
// counter so slow consumers cannot wedge the data plane.
type Bus struct {
	mu      sync.RWMutex
	subs    map[Type]map[chan any]struct{}
	dropped map[Type]int
	log     []Type
}

// NewBus returns an empty bus.
func NewBus() *Bus {
	return &Bus{subs: make(map[Type]map[chan any]struct{}), dropped: make(map[Type]int)}
}

// Subscribe registers ch for event type t.
func (b *Bus) Subscribe(t Type, ch chan any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.subs[t] == nil {
		b.subs[t] = make(map[chan any]struct{})
	}
	b.subs[t][ch] = struct{}{}
}

// Unsubscribe removes ch from event type t.
func (b *Bus) Unsubscribe(t Type, ch chan any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.subs[t], ch)
}

// Publish delivers v to all subscribers of t without blocking.
func (b *Bus) Publish(t Type, v any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.log = append(b.log, t)
	for ch := range b.subs[t] {
		select {
		case ch <- v:
		default:
			b.dropped[t]++
		}
	}
}

// Dropped reports non-blocking delivery drops per type.
func (b *Bus) Dropped(t Type) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.dropped[t]
}

// Log returns the publish history in order.
func (b *Bus) Log() []Type {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Type, len(b.log))
	copy(out, b.log)
	return out
}
