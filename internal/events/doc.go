// Package events is the process-wide event bus.
//
// Binding contract: Publish(t Type, v any) and Subscribe(t Type, ch chan any)
// with event names NODE_DISCOVERED NODE_CONNECTED NODE_DISCONNECTED
// TUNNEL_STARTED TUNNEL_STOPPED KILL_SWITCH_ENABLED DNS_CHANGED
// PAYMENT_REQUESTED PAYMENT_CONFIRMED SESSION_AUTHORIZED SESSION_EXPIRED
// NODE_HEARTBEAT CIRCUIT_ROTATED DERO_CONNECTED DERO_DISCONNECTED ERROR.
//
// Scaffold placeholder: the owning agent implements this package.
package events
