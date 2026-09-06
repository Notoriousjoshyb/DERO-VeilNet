package veilnettest

import (
	"testing"

	"github.com/dero-veilnet/veilnet/tests/ref"
)

func testMigrations() []ref.Migration {
	return []ref.Migration{
		{Version: 1, Name: "init", Up: func(s *ref.Store) error {
			s.Put("schema", "v1")
			return nil
		}},
		{Version: 2, Name: "sessions", Up: func(s *ref.Store) error {
			s.Put("sessions", "[]")
			return nil
		}},
		{Version: 3, Name: "receipts", Up: func(s *ref.Store) error {
			s.Put("receipts", "[]")
			return nil
		}},
	}
}

func TestMigrationsApplyInOrder(t *testing.T) {
	s := ref.NewStore(3)
	if err := s.Migrate(testMigrations()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if s.Version() != 3 {
		t.Fatalf("version = %d, want 3", s.Version())
	}
	for _, k := range []string{"schema", "sessions", "receipts"} {
		if _, ok := s.Get(k); !ok {
			t.Fatalf("key %q missing after migrate", k)
		}
	}
}

func TestMigrationsIdempotent(t *testing.T) {
	s := ref.NewStore(3)
	if err := s.Migrate(testMigrations()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := s.Migrate(testMigrations()); err != nil {
		t.Fatalf("re-migrate must be a no-op: %v", err)
	}
	if s.Version() != 3 {
		t.Fatalf("version = %d", s.Version())
	}
}

func TestMigrationGapAndDuplicateRejected(t *testing.T) {
	s := ref.NewStore(3)
	gap := []ref.Migration{testMigrations()[0], testMigrations()[2]}
	if err := s.Migrate(gap); err == nil {
		t.Fatal("migration gap accepted")
	}
	s2 := ref.NewStore(3)
	dup := append(append([]ref.Migration(nil), testMigrations()...), testMigrations()[1])
	if err := s2.Migrate(dup); err == nil {
		t.Fatal("duplicate migration accepted")
	}
}

func TestNewerSchemaRefused(t *testing.T) {
	old := ref.NewStore(2) // binary understands only v1..v2
	if err := old.Migrate(testMigrations()); err == nil {
		t.Fatal("schema newer than binary must be refused, not partially applied")
	}
}

func TestCrashRecoveryReplaysJournal(t *testing.T) {
	s := ref.NewStore(3)
	if err := s.Migrate(testMigrations()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	s.Put("session:abc", "active")
	s.Put("receipt:1", "paid")
	snap := s.SnapshotJournal()

	// Simulate process death: drop the store, replay the journal.
	recovered, err := ref.Recover(3, snap)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	for _, kv := range []struct{ k, want string }{
		{"schema", "v1"}, {"sessions", "[]"}, {"receipts", "[]"},
		{"session:abc", "active"}, {"receipt:1", "paid"},
	} {
		got, ok := recovered.Get(kv.k)
		if !ok || got != kv.want {
			t.Fatalf("key %q = %q, want %q", kv.k, got, kv.want)
		}
	}
}

func TestCrashRecoveryPreservesOrder(t *testing.T) {
	s := ref.NewStore(1)
	for _, v := range []string{"one", "two", "three"} {
		s.Put("counter", v)
	}
	recovered, err := ref.Recover(1, s.SnapshotJournal())
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	got, _ := recovered.Get("counter")
	if got != "three" {
		t.Fatalf("last-write-wins violated: %q", got)
	}
}
