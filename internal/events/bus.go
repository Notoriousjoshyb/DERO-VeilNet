// Package events provides the process-wide VeilNet event bus.
//
// Contract (binding): Type string, Publish(t Type, v any),
// Subscribe(t Type, ch chan any), with the event names below.
// Extra helpers (Unsubscribe, NewBus) are additive only.
package events

import "sync"

// Event names (binding contract).
const (
	NODE_DISCOVERED    Type = "NODE_DISCOVERED"
	NODE_CONNECTED     Type = "NODE_CONNECTED"
	NODE_DISCONNECTED  Type = "NODE_DISCONNECTED"
	TUNNEL_STARTED     Type = "TUNNEL_STARTED"
	TUNNEL_STOPPED     Type = "TUNNEL_STOPPED"
	KILL_SWITCH_ENABLED Type = "KILL_SWITCH_ENABLED"
	DNS_CHANGED        Type = "DNS_CHANGED"
	PAYMENT_REQUESTED  Type = "PAYMENT_REQUESTED"
	PAYMENT_CONFIRMED  Type = "PAYMENT_CONFIRMED"
	SESSION_AUTHORIZED Type = "SESSION_AUTHORIZED"
	SESSION_EXPIRED    Type = "SESSION_EXPIRED"
	NODE_HEARTBEAT     Type = "NODE_HEARTBEAT"
	CIRCUIT_ROTATED    Type = "CIRCUIT_ROTATED"
	DERO_CONNECTED     Type = "DERO_CONNECTED"
	DERO_DISCONNECTED  Type = "DERO_DISCONNECTED"
	ERROR              Type = "ERROR"
)

// Type is an event name.
type Type string

// Bus is a concurrent-safe fan-out bus with non-blocking delivery.
// A slow subscriber drops the event rather than stalling publishers.
type Bus struct {
	mu   sync.RWMutex
	subs map[Type]map[chan any]struct{}
}

// NewBus returns an empty Bus.
func NewBus() *Bus {
	return &Bus{subs: make(map[Type]map[chan any]struct{})}
}

var std = NewBus()

// Publish delivers v to all subscribers of t. Never blocks.
func Publish(t Type, v any) { std.Publish(t, v) }

// Subscribe registers ch for events of type t.
func Subscribe(t Type, ch chan any) { std.Subscribe(t, ch) }

// Unsubscribe removes ch from t (additive helper).
func Unsubscribe(t Type, ch chan any) { std.Unsubscribe(t, ch) }

// Publish delivers v to all subscribers of t. Never blocks.
func (b *Bus) Publish(t Type, v any) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.subs[t] {
		select {
		case ch <- v:
		default:
		}
	}
}

// Subscribe registers ch for events of type t.
func (b *Bus) Subscribe(t Type, ch chan any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.subs[t] == nil {
		b.subs[t] = make(map[chan any]struct{})
	}
	b.subs[t][ch] = struct{}{}
}

// Unsubscribe removes ch from t.
func (b *Bus) Unsubscribe(t Type, ch chan any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if m := b.subs[t]; m != nil {
		delete(m, ch)
	}
}
