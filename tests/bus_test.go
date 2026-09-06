package veilnettest

import (
	"testing"
	"time"

	"github.com/dero-veilnet/veilnet/tests/ref"
)

func TestBusDeliversSubscribedEvents(t *testing.T) {
	b := ref.NewBus()
	ch := make(chan any, 4)
	b.Subscribe(ref.TunnelStarted, ch)
	b.Subscribe(ref.TunnelStopped, ch)
	b.Publish(ref.TunnelStarted, "up")
	b.Publish(ref.NodeHeartbeat, "ignored-by-this-subscriber")

	select {
	case v := <-ch:
		if v != "up" {
			t.Fatalf("payload = %v", v)
		}
	case <-time.After(time.Second):
		t.Fatal("subscribed event not delivered")
	}
	select {
	case v := <-ch:
		t.Fatalf("unsubscribed type leaked payload %v", v)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestBusUnsubscribeStopsDelivery(t *testing.T) {
	b := ref.NewBus()
	ch := make(chan any, 4)
	b.Subscribe(ref.SessionExpired, ch)
	b.Unsubscribe(ref.SessionExpired, ch)
	b.Publish(ref.SessionExpired, "x")
	select {
	case v := <-ch:
		t.Fatalf("got %v after unsubscribe", v)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestBusNeverBlocksSlowConsumer(t *testing.T) {
	b := ref.NewBus()
	full := make(chan any) // unbuffered, nobody reading
	b.Subscribe(ref.NodeHeartbeat, full)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			b.Publish(ref.NodeHeartbeat, "beat")
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Publish blocked on slow consumer")
	}
	if b.Dropped(ref.NodeHeartbeat) == 0 {
		t.Fatal("expected drop accounting for undrained subscriber")
	}
}

func TestBusContractEventNamesComplete(t *testing.T) {
	if len(ref.AllTypes) != 16 {
		t.Fatalf("event count = %d, want 16 contract names", len(ref.AllTypes))
	}
	want := map[ref.Type]bool{
		"NODE_DISCOVERED": true, "NODE_CONNECTED": true, "NODE_DISCONNECTED": true,
		"TUNNEL_STARTED": true, "TUNNEL_STOPPED": true, "KILL_SWITCH_ENABLED": true,
		"DNS_CHANGED": true, "PAYMENT_REQUESTED": true, "PAYMENT_CONFIRMED": true,
		"SESSION_AUTHORIZED": true, "SESSION_EXPIRED": true, "NODE_HEARTBEAT": true,
		"CIRCUIT_ROTATED": true, "DERO_CONNECTED": true, "DERO_DISCONNECTED": true,
		"ERROR": true,
	}
	for _, et := range ref.AllTypes {
		if !want[et] {
			t.Fatalf("unexpected event name %q", et)
		}
		delete(want, et)
	}
	if len(want) != 0 {
		t.Fatalf("missing event names: %v", want)
	}
}
