// Watchdog, reconnect backoff and sleep/wake detection for the tunnel engine.
//
// The loop polls the backend (real device counters) every pollInterval:
//   - fresh handshake (or first sighting) -> UP, backoff reset.
//   - stale/missing handshake -> rebind + exponential backoff; after
//     maxRetries consecutive failures -> FAILED + ERROR event (fail-closed
//     signal for the kill-switch layer).
//   - probe errors count as failures but never fabricate UP.
//
// Sleep/wake: without importing platform power APIs, a wall-clock jump far
// beyond the poll interval is treated as a suspend/resume cycle and forces
// an immediate rebind (UDP sockets rarely survive sleep). The service layer
// can additionally call Engine.Wake on WM_POWERBROADCAST.
package tunnel

import (
	"time"

	"github.com/dero-veilnet/veilnet/internal/events"
)

// backoff bounds the reconnect delay.
const (
	minBackoff = time.Second
	maxBackoff = time.Minute
)

// watchdogLoop runs until stop is closed.
func (e *engine) watchdogLoop(stop <-chan struct{}) {
	defer e.wg.Done()
	ticker := time.NewTicker(e.pollInterval)
	defer ticker.Stop()
	lastTick := time.Now()
	wakeGap := 5*e.pollInterval + 60*time.Second

	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			if now.Sub(lastTick) > wakeGap {
				e.onWakeDetected()
			}
			lastTick = now
			e.step(now)
		}
	}
}

// onWakeDetected handles a suspected sleep/wake cycle.
func (e *engine) onWakeDetected() {
	e.mu.RLock()
	be := e.backend
	e.mu.RUnlock()
	if be == nil {
		return
	}
	_ = be.rebind()
	e.mu.Lock()
	e.retries = 0
	e.mu.Unlock()
	if h := e.onWake; h != nil {
		h()
	}
}

// step performs one poll + state transition.
func (e *engine) step(now time.Time) {
	e.mu.RLock()
	be := e.backend
	staleAfter := e.staleAfter
	maxRetries := e.maxRetries
	e.mu.RUnlock()
	if be == nil {
		return
	}

	rx, tx, hs, err := be.probe()
	e.mu.Lock()
	defer e.mu.Unlock()

	if err != nil {
		e.noteFailureLocked(now, maxRetries)
		return
	}
	// Monotonic guard: drivers occasionally report stale snapshots.
	if rx > e.rx {
		e.rx = rx
	}
	if tx > e.tx {
		e.tx = tx
	}
	switch {
	case !hs.IsZero() && now.Sub(hs) <= staleAfter:
		if !hs.After(e.lastHS) && e.state == UP {
			return // steady state
		}
		e.lastHS = hs
		e.retries = 0
		e.setLocked(UP, e.since)
	case !hs.IsZero():
		// Handshake exists but is stale: try to recover.
		e.lastHS = hs
		e.recoverLocked(now, maxRetries)
	default:
		// No handshake yet: stay CONNECTING during the grace window,
		// then treat like a failure so a dead peer cannot wedge us.
		if now.Sub(e.since) > staleAfter {
			e.recoverLocked(now, maxRetries)
		} else if e.state != CONNECTING && e.state != UP {
			e.setLocked(CONNECTING, now)
		}
	}
}

// recoverLocked rebinds with backoff and fails over to FAILED.
func (e *engine) recoverLocked(now time.Time, maxRetries int) {
	be := e.backend
	if be != nil {
		_ = be.rebind()
	}
	e.noteFailureLocked(now, maxRetries)
}

// noteFailureLocked backs off and eventually marks FAILED (fail-closed).
func (e *engine) noteFailureLocked(now time.Time, maxRetries int) {
	e.retries++
	if e.retries > maxRetries {
		if e.state != FAILED {
			e.setLocked(FAILED, now)
			// Publish outside any assumption about subscribers; the bus
			// never blocks.
			go events.Publish(events.ERROR, map[string]any{
				"op":    "tunnel",
				"error": "handshake watchdog: retries exhausted",
				"state": string(FAILED),
			})
		}
		return
	}
	if e.state == UP {
		// Drop back to CONNECTING while recovering; the kill-switch layer
		// treats non-UP as untrusted and keeps blocking.
		e.setLocked(CONNECTING, now)
	}
}

// backoffFor returns the reconnect delay for a failure count (pure, tested).
func backoffFor(failures int) time.Duration {
	d := minBackoff
	for i := 1; i < failures && d < maxBackoff; i++ {
		d *= 2
	}
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}
