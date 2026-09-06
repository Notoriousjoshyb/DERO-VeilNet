package nodes

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Retained fields note: the authorized-clients table keeps ONLY
// accounting metadata (token/session IDs, pubkey, assigned IP,
// endpoint address, scope, timestamps, byte counters). It NEVER stores
// traffic content, DNS names, or URLs. See docs/NODE_OPERATOR.md.

// EnsureMgmtToken loads the mgmt bearer token, generating and storing
// 32 random bytes (hex) on first run. File mode 0600.
func EnsureMgmtToken(path string) (string, error) {
	if path == "" {
		path = MgmtTokenPath()
	}
	if data, err := os.ReadFile(path); err == nil {
		tok := string(data)
		if len(tok) >= 32 {
			return tok, nil
		}
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("nodes: random token: %w", err)
	}
	tok := hex.EncodeToString(raw[:])
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(tok), 0o600); err != nil {
		return "", err
	}
	return tok, nil
}

// CheckBearer compares a presented token in constant time.
func CheckBearer(expected, presented string) bool {
	if expected == "" || presented == "" {
		return false
	}
	if len(expected) != len(presented) {
		// Compare anyway over the expected bytes to avoid length oracle
		// shaping, then fail.
		_ = subtle.ConstantTimeCompare([]byte(expected), []byte(expected))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) == 1
}

// Store persists authorized clients + counters in SQLite.
type Store struct {
	db *sql.DB
}

// OpenStore opens (creating dirs) the sqlite database and schema.
func OpenStore(path string) (*Store, error) {
	if path == "" {
		path = DefaultDBPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("nodes: open db: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS authorized_clients (
		token_id TEXT PRIMARY KEY,
		node_id TEXT NOT NULL DEFAULT '',
		session_id TEXT NOT NULL DEFAULT '',
		client_pubkey TEXT NOT NULL,
		assigned_ip TEXT NOT NULL DEFAULT '',
		endpoint TEXT NOT NULL DEFAULT '',
		scope TEXT NOT NULL DEFAULT 'exit',
		expires_at INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL DEFAULT 0,
		revoked INTEGER NOT NULL DEFAULT 0,
		rx_bytes INTEGER NOT NULL DEFAULT 0,
		tx_bytes INTEGER NOT NULL DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS node_counters (
		name TEXT PRIMARY KEY,
		value INTEGER NOT NULL DEFAULT 0
	);`)
	return err
}

// ClientRow is one authorized-clients row.
type ClientRow struct {
	TokenID     string
	NodeID      string
	SessionID   string
	ClientKey   string
	AssignedIP  string
	Endpoint    string
	Scope       string
	ExpiresAt   time.Time
	CreatedAt   time.Time
	Revoked     bool
	RxBytes     uint64
	TxBytes     uint64
}

// UpsertClient inserts or replaces a client row.
func (s *Store) UpsertClient(r ClientRow) error {
	revoked := 0
	if r.Revoked {
		revoked = 1
	}
	_, err := s.db.Exec(`INSERT INTO authorized_clients
		(token_id, node_id, session_id, client_pubkey, assigned_ip, endpoint, scope, expires_at, created_at, revoked, rx_bytes, tx_bytes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(token_id) DO UPDATE SET
			node_id=excluded.node_id, session_id=excluded.session_id,
			client_pubkey=excluded.client_pubkey, assigned_ip=excluded.assigned_ip,
			endpoint=excluded.endpoint, scope=excluded.scope,
			expires_at=excluded.expires_at, revoked=excluded.revoked`,
		r.TokenID, r.NodeID, r.SessionID, r.ClientKey, r.AssignedIP, r.Endpoint,
		r.Scope, r.ExpiresAt.Unix(), r.CreatedAt.Unix(), revoked, r.RxBytes, r.TxBytes)
	return err
}

// RevokeClient marks a token revoked and frees its slot.
func (s *Store) RevokeClient(tokenID string) error {
	_, err := s.db.Exec(`UPDATE authorized_clients SET revoked=1 WHERE token_id=?`, tokenID)
	return err
}

// AddBytes accumulates counters for a token.
func (s *Store) AddBytes(tokenID string, rx, tx uint64) error {
	_, err := s.db.Exec(`UPDATE authorized_clients SET rx_bytes=rx_bytes+?, tx_bytes=tx_bytes+? WHERE token_id=?`, rx, tx, tokenID)
	return err
}

// CountActive counts non-revoked, non-expired rows.
func (s *Store) CountActive(now time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM authorized_clients WHERE revoked=0 AND (expires_at=0 OR expires_at>?)`, now.Unix()).Scan(&n)
	return n, err
}

// ListActive returns non-revoked rows (for IPAM restore / diagnostics).
func (s *Store) ListActive() ([]ClientRow, error) {
	rows, err := s.db.Query(`SELECT token_id, node_id, session_id, client_pubkey, assigned_ip, endpoint, scope, expires_at, created_at, revoked, rx_bytes, tx_bytes
		FROM authorized_clients WHERE revoked=0 ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClientRow
	for rows.Next() {
		var r ClientRow
		var exp, created, revoked, rx, tx int64
		if err := rows.Scan(&r.TokenID, &r.NodeID, &r.SessionID, &r.ClientKey, &r.AssignedIP, &r.Endpoint, &r.Scope, &exp, &created, &revoked, &rx, &tx); err != nil {
			return nil, err
		}
		r.ExpiresAt = time.Unix(exp, 0)
		r.CreatedAt = time.Unix(created, 0)
		r.Revoked = revoked != 0
		r.RxBytes, r.TxBytes = uint64(rx), uint64(tx)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Totals sums byte counters over all rows.
func (s *Store) Totals() (rx, tx uint64, err error) {
	var r, t sql.NullInt64
	if err := s.db.QueryRow(`SELECT SUM(rx_bytes), SUM(tx_bytes) FROM authorized_clients`).Scan(&r, &t); err != nil {
		return 0, 0, err
	}
	return uint64(r.Int64), uint64(t.Int64), nil
}

// BumpSessionsToday increments the per-day session counter.
func (s *Store) BumpSessionsToday(day string) error {
	_, err := s.db.Exec(`INSERT INTO node_counters(name, value) VALUES(?, 1)
		ON CONFLICT(name) DO UPDATE SET value=value+1`, "sessions:"+day)
	return err
}

// SessionsToday reads the per-day session counter.
func (s *Store) SessionsToday(day string) int {
	var n int
	if err := s.db.QueryRow(`SELECT value FROM node_counters WHERE name=?`, "sessions:"+day).Scan(&n); err != nil {
		return 0
	}
	return n
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }
