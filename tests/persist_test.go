package veilnettest

// SQLite-backed persistence: schema migrations and crash durability against
// the real modernc.org/sqlite driver (no cgo). These complement the
// driver-agnostic ordering/journal semantics in store_test.go with proof
// that the actual storage engine honors them.

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func openDevDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

var sqlMigrations = []struct {
	version int
	name    string
	up      string
}{
	{1, "init", `CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT NOT NULL)`},
	{2, "sessions", `CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, node_id TEXT NOT NULL, expires_at INTEGER NOT NULL)`},
	{3, "receipts", `CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY, session_id TEXT NOT NULL, amount INTEGER NOT NULL)`},
}

func migrateSQL(t *testing.T, db *sql.DB) int {
	t.Helper()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_version(v INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("version table: %v", err)
	}
	var current int
	if err := db.QueryRow(`SELECT COALESCE(MAX(v),0) FROM schema_version`).Scan(&current); err != nil {
		t.Fatalf("read version: %v", err)
	}
	for _, m := range sqlMigrations {
		if m.version <= current {
			continue
		}
		if m.version != current+1 {
			t.Fatalf("migration gap at v%d", m.version)
		}
		tx, err := db.Begin()
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if _, err := tx.Exec(m.up); err != nil {
			tx.Rollback()
			t.Fatalf("migration %d (%s): %v", m.version, m.name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_version(v) VALUES(?)`, m.version); err != nil {
			tx.Rollback()
			t.Fatalf("record version: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit v%d: %v", m.version, err)
		}
		current = m.version
	}
	return current
}

func TestSQLiteMigrationsReachV3(t *testing.T) {
	db := openDevDB(t, "veilnet.db")
	if v := migrateSQL(t, db); v != 3 {
		t.Fatalf("schema version = %d, want 3", v)
	}
	for _, table := range []string{"kv", "sessions", "receipts", "schema_version"} {
		var name string
		if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name); err != nil {
			t.Fatalf("table %s missing: %v", table, err)
		}
	}
}

func TestSQLiteMigrationsIdempotent(t *testing.T) {
	db := openDevDB(t, "veilnet.db")
	migrateSQL(t, db)
	if v := migrateSQL(t, db); v != 3 {
		t.Fatalf("re-migrate version = %d, want 3", v)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_version`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 3 {
		t.Fatalf("version rows = %d, want 3 (re-migrate duplicated)", count)
	}
}

func TestSQLiteCrashDurabilityAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "veilnet.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	migrateSQL(t, db)
	if _, err := db.Exec(`INSERT INTO sessions(id, node_id, expires_at) VALUES(?,?,?)`, "sess1", "nodeA", 9999999999); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO receipts(id, session_id, amount) VALUES(?,?,?)`, "rcpt1", "sess1", 5000000000); err != nil {
		t.Fatalf("insert: %v", err)
	}
	db.Close() // simulate process death: no checkpoint ceremony, just close

	// Reopen cold: committed rows must survive.
	db2, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	var node string
	if err := db2.QueryRow(`SELECT node_id FROM sessions WHERE id='sess1'`).Scan(&node); err != nil {
		t.Fatalf("session lost across restart: %v", err)
	}
	if node != "nodeA" {
		t.Fatalf("session node = %q", node)
	}
	var amount int64
	if err := db2.QueryRow(`SELECT amount FROM receipts WHERE id='rcpt1'`).Scan(&amount); err != nil {
		t.Fatalf("receipt lost across restart: %v", err)
	}
	if amount != 5000000000 {
		t.Fatalf("receipt amount = %d", amount)
	}
	if v := migrateSQL(t, db2); v != 3 {
		t.Fatalf("post-crash version = %d", v)
	}
}

func TestSQLiteUncommittedLostOnRollback(t *testing.T) {
	db := openDevDB(t, "veilnet.db")
	migrateSQL(t, db)
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO sessions(id, node_id, expires_at) VALUES(?,?,?)`, "ghost", "nodeA", 1); err != nil {
		t.Fatalf("insert: %v", err)
	}
	tx.Rollback() // crash before commit
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE id='ghost'`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatal("uncommitted write survived rollback")
	}
}
