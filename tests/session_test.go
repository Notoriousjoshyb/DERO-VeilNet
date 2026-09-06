package veilnettest

import (
	"testing"
	"time"

	"github.com/dero-veilnet/veilnet/tests/ref"
)

func newSessionWorld() (*ref.Manager, *ref.Sessions, *ref.Bus) {
	bus := ref.NewBus()
	tokens := ref.NewManager()
	return tokens, ref.NewSessions(tokens, bus), bus
}

func TestSessionAuthorizeEmitsEvent(t *testing.T) {
	tokens, sessions, bus := newSessionWorld()
	ch := make(chan any, 4)
	bus.Subscribe(ref.SessionAuthorized, ch)
	_, bearer, err := tokens.Issue("nodeA", "sess1", "connect", time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	id, secret, err := ref.SplitBearer(bearer)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	sess, err := sessions.Authorize(id, secret)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if sess.ID != "sess1" || !sessions.Alive("sess1") {
		t.Fatalf("session = %+v", sess)
	}
	select {
	case v := <-ch:
		if v != "sess1" {
			t.Fatalf("event payload = %v", v)
		}
	default:
		t.Fatal("SESSION_AUTHORIZED not emitted")
	}
}

func TestSessionTokenSingleUseAcrossAuthorize(t *testing.T) {
	tokens, sessions, _ := newSessionWorld()
	_, bearer, err := tokens.Issue("nodeA", "sess1", "connect", time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	id, secret, _ := ref.SplitBearer(bearer)
	if _, err := sessions.Authorize(id, secret); err != nil {
		t.Fatalf("first Authorize: %v", err)
	}
	if _, err := sessions.Authorize(id, secret); err == nil {
		t.Fatal("same token authorized twice")
	}
}

func TestSessionHeartbeatExpiryAndSweep(t *testing.T) {
	tokens, sessions, bus := newSessionWorld()
	now := time.Now()
	sessions.SetClock(func() time.Time { return now })
	expired := make(chan any, 4)
	bus.Subscribe(ref.SessionExpired, expired)

	_, bearer, err := tokens.Issue("nodeA", "sess1", "connect", time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	id, secret, _ := ref.SplitBearer(bearer)
	if _, err := sessions.Authorize(id, secret); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	// Heartbeat keeps it alive inside the 30s tolerance.
	now = now.Add(20 * time.Second)
	if err := sessions.Heartbeat("sess1"); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	now = now.Add(20 * time.Second)
	if !sessions.Alive("sess1") {
		t.Fatal("session died despite heartbeat inside tolerance")
	}
	// Silence past tolerance expires it exactly once.
	now = now.Add(31 * time.Second)
	if sessions.Alive("sess1") {
		t.Fatal("stale session still alive")
	}
	swept := sessions.Sweep()
	if len(swept) != 1 || swept[0] != "sess1" {
		t.Fatalf("swept = %v", swept)
	}
	select {
	case v := <-expired:
		if v != "sess1" {
			t.Fatalf("expired payload = %v", v)
		}
	default:
		t.Fatal("SESSION_EXPIRED not emitted")
	}
	if again := sessions.Sweep(); len(again) != 0 {
		t.Fatalf("second sweep re-emitted: %v", again)
	}
}

func TestSessionUnknownHeartbeatRejected(t *testing.T) {
	_, sessions, _ := newSessionWorld()
	if err := sessions.Heartbeat("nope"); err == nil {
		t.Fatal("heartbeat on unknown session accepted")
	}
	if sessions.Alive("nope") {
		t.Fatal("unknown session alive")
	}
}

func TestSessionReconnectAfterTunnelBounce(t *testing.T) {
	tokens, sessions, _ := newSessionWorld()
	_, bearer, err := tokens.Issue("nodeA", "sess1", "connect", time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	id, secret, _ := ref.SplitBearer(bearer)
	if _, err := sessions.Authorize(id, secret); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	// A tunnel bounce is transparent to the session layer as long as
	// heartbeats keep flowing: prove liveness survives engine restart.
	engine := ref.NewFakeEngine()
	if err := engine.Start(goodConfig()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	engine.Handshake()
	if err := engine.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := engine.Start(goodConfig()); err != nil {
		t.Fatalf("reconnect Start: %v", err)
	}
	engine.Handshake()
	if err := sessions.Heartbeat("sess1"); err != nil {
		t.Fatalf("Heartbeat after bounce: %v", err)
	}
	if !sessions.Alive("sess1") {
		t.Fatal("session lost across tunnel reconnect")
	}
}
