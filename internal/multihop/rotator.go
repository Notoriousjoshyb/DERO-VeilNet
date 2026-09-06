package multihop

import (
	"errors"
	"sync"
	"time"
)

// RotationRecord logs one entry rotation for local diagnostics.
type RotationRecord struct {
	At       time.Time
	OldEntry string
	NewEntry string
	ExitKept string
	Reason   string
}

// Rotator holds the active circuit and swaps the ENTRY hop on demand.
// The EXIT hop is preserved across rotations so long-lived exit sessions
// (payments, tokens) survive entry churn. Rotation never touches the
// data plane directly: it rebuilds + verifies the circuit and invokes
// OnRotated so the app layer can reprogram tunnel/routing/firewall and
// publish events.CIRCUIT_ROTATED. It never imports those packages itself.
type Rotator struct {
	mu        sync.Mutex
	current   *Circuit
	history   []RotationRecord
	onRotated func(old, next *Circuit)
}

// NewRotator wraps an already built + verified circuit.
func NewRotator(initial *Circuit, onRotated func(old, next *Circuit)) (*Rotator, error) {
	if initial == nil {
		return nil, errors.New("multihop: rotator needs an initial circuit")
	}
	if err := initial.Verify(); err != nil {
		return nil, err
	}
	return &Rotator{current: initial, onRotated: onRotated}, nil
}

// Current returns the active circuit.
func (r *Rotator) Current() *Circuit {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current
}

// History returns a copy of the rotation log.
func (r *Rotator) History() []RotationRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]RotationRecord(nil), r.history...)
}

// RotateEntry swaps the ENTRY hop, keeps downstream hops (EXIT, plus MIDDLE
// on 3-hop circuits), rebuilds and verifies before committing.
// Single-hop circuits rotate by replacing their single node. On success
// the OnRotated callback fires with (old, new); if the callback is nil
// the caller must still reprogram the data plane from Current().
// NOTE: entry rotation exposes the client IP to a new observer; prefer
// RotateExit (guard-aware) unless the guard itself is compromised or due.
func (r *Rotator) RotateEntry(newEntry NodeInfo, reason string) (*Circuit, error) {
	if err := newEntry.Validate(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	old := r.current
	var next *Circuit
	var err error
	switch old.Hops {
	case 1:
		next, err = BuildSingleHop(newEntry)
	case 3:
		next, err = BuildThreeHopCircuit(newEntry, old.Middle, old.Exit)
	default:
		if newEntry.NodeID == old.Exit.NodeID {
			r.mu.Unlock()
			return nil, errors.New("multihop: new entry must differ from exit")
		}
		next, err = BuildTwoHop(newEntry, old.Exit)
	}
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	if err := next.Verify(); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	r.current = next
	r.history = append(r.history, RotationRecord{
		At:       time.Now().UTC(),
		OldEntry: old.Entry.NodeID,
		NewEntry: next.Entry.NodeID,
		ExitKept: next.Exit.NodeID,
		Reason:   reason,
	})
	cb := r.onRotated
	r.mu.Unlock()
	if cb != nil {
		cb(old, next)
	}
	return next, nil
}

// RotateExit swaps the EXIT hop, keeps the ENTRY (and MIDDLE on 3-hop
// circuits), rebuilds and verifies before committing. This is the
// guard-aware direction: the entry observer never changes, so the client
// IP is never exposed to a new entry. Single-hop circuits rotate by
// replacing their single node. On success OnRotated fires with (old, new).
func (r *Rotator) RotateExit(newExit NodeInfo, reason string) (*Circuit, error) {
	if err := newExit.Validate(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	old := r.current
	var next *Circuit
	var err error
	switch old.Hops {
	case 1:
		next, err = BuildSingleHop(newExit)
	case 3:
		next, err = BuildThreeHopCircuit(old.Entry, old.Middle, newExit)
	default:
		next, err = BuildTwoHop(old.Entry, newExit)
	}
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	if err := next.Verify(); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	r.current = next
	r.history = append(r.history, RotationRecord{
		At:       time.Now().UTC(),
		OldEntry: old.Entry.NodeID,
		NewEntry: next.Entry.NodeID,
		ExitKept: "",
		Reason:   reason,
	})
	cb := r.onRotated
	r.mu.Unlock()
	if cb != nil {
		cb(old, next)
	}
	return next, nil
}

// RotateDownstream swaps MIDDLE+EXIT on a 3-hop circuit, keeps the guard
// entry, rebuilds and verifies. Rejected on shorter circuits. On success
// OnRotated fires with (old, new).
func (r *Rotator) RotateDownstream(newMiddle, newExit NodeInfo, reason string) (*Circuit, error) {
	r.mu.Lock()
	old := r.current
	if old.Hops != 3 {
		r.mu.Unlock()
		return nil, errors.New("multihop: downstream rotation needs a 3-hop circuit")
	}
	entry := old.Entry
	r.mu.Unlock()
	next, err := BuildThreeHopCircuit(entry, newMiddle, newExit)
	if err != nil {
		return nil, err
	}
	if err := next.Verify(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.current = next
	r.history = append(r.history, RotationRecord{
		At:       time.Now().UTC(),
		OldEntry: old.Entry.NodeID,
		NewEntry: next.Entry.NodeID,
		ExitKept: "",
		Reason:   reason,
	})
	cb := r.onRotated
	r.mu.Unlock()
	if cb != nil {
		cb(old, next)
	}
	return next, nil
}
