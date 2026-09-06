package ref

import (
	"errors"
	"sync"
	"time"
)

// Session mirrors authorized client sessions bound to single-use tokens.
type Session struct {
	ID        string
	NodeID    string
	ExpiresAt time.Time
	LastBeat  time.Time
	Scope     string
}

// Sessions manages authorize/heartbeat/expire with a pluggable clock.
type Sessions struct {
	mu       sync.Mutex
	items    map[string]*Session
	tokens   *Manager
	bus      *Bus
	now      func() time.Time
	beatTTL  time.Duration
}

// NewSessions returns a manager with 30s heartbeat tolerance.
func NewSessions(tokens *Manager, bus *Bus) *Sessions {
	return &Sessions{
		items:   make(map[string]*Session),
		tokens:  tokens,
		bus:     bus,
		now:     time.Now,
		beatTTL: 30 * time.Second,
	}
}

// SetClock overrides time for expiry testing.
func (s *Sessions) SetClock(fn func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = fn
}

// Authorize consumes a single-use token and opens a session, emitting
// SESSION_AUTHORIZED. Reused/expired/forged tokens are refused.
func (s *Sessions) Authorize(tokenID, secret string) (*Session, error) {
	t, err := s.tokens.Consume(tokenID, secret)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	sess := &Session{
		ID:        t.SessionID,
		NodeID:    t.NodeID,
		ExpiresAt: t.ExpiresAt,
		LastBeat:  now,
		Scope:     t.Scope,
	}
	s.items[sess.ID] = sess
	if s.bus != nil {
		s.bus.Publish(SessionAuthorized, sess.ID)
	}
	return sess, nil
}

// Heartbeat refreshes liveness; a session silent past beatTTL is expired.
func (s *Sessions) Heartbeat(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.items[id]
	if !ok {
		return errors.New("ref: unknown session")
	}
	sess.LastBeat = s.now()
	if s.bus != nil {
		s.bus.Publish(NodeHeartbeat, id)
	}
	return nil
}

// Alive reports whether id exists, is unexpired, and beat within tolerance.
func (s *Sessions) Alive(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.items[id]
	if !ok {
		return false
	}
	now := s.now()
	if !now.Before(sess.ExpiresAt) {
		return false
	}
	return now.Sub(sess.LastBeat) <= s.beatTTL
}

// Sweep expires dead sessions, emitting SESSION_EXPIRED once each.
// Returns the expired ids.
func (s *Sessions) Sweep() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out []string
	for id, sess := range s.items {
		if !now.Before(sess.ExpiresAt) || now.Sub(sess.LastBeat) > s.beatTTL {
			delete(s.items, id)
			out = append(out, id)
			if s.bus != nil {
				s.bus.Publish(SessionExpired, id)
			}
		}
	}
	return out
}
