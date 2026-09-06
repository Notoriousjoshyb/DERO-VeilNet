package ref

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Migration is one ordered schema step with a monotonically increasing
// version. Up must be idempotent: applying twice is a no-op.
type Migration struct {
	Version int
	Name    string
	Up      func(s *Store) error
}

// Store is a minimal versioned key/value with an append-only journal.
// Every mutating op appends a journal record first (write-ahead), so a crash
// replay restores all committed writes. Migrations gate startup: the store
// refuses to open when its schema is newer than the binary understands.
type Store struct {
	mu       sync.Mutex
	version  int
	data     map[string]string
	journal  []journalEntry
	binaryMax int
}

type journalEntry struct {
	seq   int
	key   string
	value string
}

// NewStore opens at binaryMax schema version.
func NewStore(binaryMax int) *Store {
	return &Store{data: make(map[string]string), binaryMax: binaryMax}
}

// Migrate applies pending migrations in version order, rejecting gaps,
// duplicates, and schemas newer than the binary.
func (s *Store) Migrate(ms []Migration) error {
	ordered := append([]Migration(nil), ms...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Version < ordered[j].Version })
	// Plan under lock; run Up calls unlocked (Up writes via Put, which
	// locks per-op). Holding the mutex across Up would self-deadlock.
	s.mu.Lock()
	seen := map[int]bool{}
	var pending []Migration
	next := s.version + 1
	for _, m := range ordered {
		if seen[m.Version] {
			s.mu.Unlock()
			return fmt.Errorf("ref: duplicate migration %d", m.Version)
		}
		seen[m.Version] = true
		if m.Version > s.binaryMax {
			s.mu.Unlock()
			return fmt.Errorf("ref: schema v%d newer than binary v%d", m.Version, s.binaryMax)
		}
		if m.Version < next {
			continue
		}
		if m.Version != next {
			s.mu.Unlock()
			return fmt.Errorf("ref: migration gap at v%d", m.Version)
		}
		pending = append(pending, m)
		next++
	}
	s.mu.Unlock()
	for _, m := range pending {
		if err := m.Up(s); err != nil {
			return fmt.Errorf("ref: migration v%d failed: %w", m.Version, err)
		}
		s.mu.Lock()
		if m.Version > s.version {
			s.version = m.Version
		}
		s.mu.Unlock()
	}
	return nil
}

// Version reports the applied schema version.
func (s *Store) Version() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version
}

// Put commits a write-ahead journal record then applies it.
func (s *Store) Put(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.journal = append(s.journal, journalEntry{seq: len(s.journal), key: key, value: value})
	s.data[key] = value
}

// Get reads committed state.
func (s *Store) Get(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	return v, ok
}

// SnapshotJournal copies committed records for crash simulation.
func (s *Store) SnapshotJournal() []struct{ Key, Value string } {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]struct{ Key, Value string }, len(s.journal))
	for i, e := range s.journal {
		out[i].Key, out[i].Value = e.key, e.value
	}
	return out
}

// Recover replays a journal snapshot into a fresh store, restoring every
// committed write in order. Journal records newer than binaryMax schema
// markers are rejected rather than silently applied.
func Recover(binaryMax int, snapshot []struct{ Key, Value string }) (*Store, error) {
	if snapshot == nil {
		return nil, errors.New("ref: nil journal snapshot")
	}
	s := NewStore(binaryMax)
	for _, e := range snapshot {
		s.Put(e.Key, e.Value)
	}
	return s, nil
}
