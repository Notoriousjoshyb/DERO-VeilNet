// Package storage persists client state in SQLite (modernc.org/sqlite):
// saved nodes, latency history, local trust, connection history,
// receipts, settings, and session state. Schema is versioned via
// migrations from version 0 to SchemaVersion.
package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// SchemaVersion is the current migration level.
const SchemaVersion = 3

// migrations upgrades the schema step by step.
var migrations = []string{
	`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
	CREATE TABLE IF NOT EXISTS saved_nodes (
		node_id TEXT PRIMARY KEY,
		wg_pubkey TEXT NOT NULL DEFAULT '',
		region TEXT NOT NULL DEFAULT '',
		country TEXT NOT NULL DEFAULT '',
		city TEXT NOT NULL DEFAULT '',
		endpoint TEXT NOT NULL DEFAULT '',
		price_per_hour_dero REAL NOT NULL DEFAULT 0,
		capacity_max_clients INTEGER NOT NULL DEFAULT 0,
		protocol_version INTEGER NOT NULL DEFAULT 0,
		bond_dero REAL NOT NULL DEFAULT 0,
		status TEXT NOT NULL DEFAULT '',
		version TEXT NOT NULL DEFAULT '',
		last_seen DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
		fail_count INTEGER NOT NULL DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS latency_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		node_id TEXT NOT NULL,
		latency_ms INTEGER NOT NULL,
		at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	);
	CREATE INDEX IF NOT EXISTS idx_latency_node ON latency_history(node_id, at);
	CREATE TABLE IF NOT EXISTS local_trust (
		node_id TEXT PRIMARY KEY,
		score REAL NOT NULL DEFAULT 0.5,
		samples INTEGER NOT NULL DEFAULT 0,
		updated_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	);
	CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');
	CREATE TABLE IF NOT EXISTS session_state (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '');`,
	`CREATE TABLE IF NOT EXISTS connection_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		node_id TEXT NOT NULL,
		started_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
		ended_at DATETIME,
		rx_bytes INTEGER NOT NULL DEFAULT 0,
		tx_bytes INTEGER NOT NULL DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_conn_node ON connection_history(node_id, started_at);`,
	`CREATE TABLE IF NOT EXISTS receipts (
		id TEXT PRIMARY KEY,
		node_id TEXT NOT NULL DEFAULT '',
		session_id TEXT NOT NULL DEFAULT '',
		amount_dero REAL NOT NULL DEFAULT 0,
		txid TEXT NOT NULL DEFAULT '',
		at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
	);`,
}

// Store wraps the client database.
type Store struct {
	db *sql.DB
}

// ClientDBPath returns ~/.veilnet/client.db.
func ClientDBPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".veilnet", "client.db"), nil
}

// Open creates parent dirs, opens the DB, and runs migrations.
func Open(path string) (*Store, error) {
	if path == "" {
		p, err := ClientDBPath()
		if err != nil {
			return nil, err
		}
		path = p
	}
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("init schema_version: %w", err)
	}
	var v int
	switch err := s.db.QueryRow(`SELECT version FROM schema_version LIMIT 1`).Scan(&v); {
	case err == sql.ErrNoRows:
		if _, err := s.db.Exec(`INSERT INTO schema_version(version) VALUES (0)`); err != nil {
			return fmt.Errorf("init schema_version: %w", err)
		}
		v = 0
	case err != nil:
		return fmt.Errorf("read schema_version: %w", err)
	}
	for v < len(migrations) {
		if _, err := s.db.Exec(migrations[v]); err != nil {
			return fmt.Errorf("migration %d: %w", v+1, err)
		}
		v++
		if _, err := s.db.Exec(`UPDATE schema_version SET version=?`, v); err != nil {
			return err
		}
	}
	return nil
}

// Node mirrors registry metadata plus local observations.
type Node struct {
	NodeID            string
	WGPubkey          string
	Region            string
	Country           string
	City              string
	Endpoint          string
	PricePerHourDero  float64
	CapacityMaxClients int
	ProtocolVersion   int
	BondDero          float64
	Status            string
	Version           string
	LastSeen          time.Time
	FailCount         int
}

// SaveNode inserts or replaces a node record.
func (s *Store) SaveNode(n Node) error {
	_, err := s.db.Exec(`INSERT INTO saved_nodes
		(node_id, wg_pubkey, region, country, city, endpoint, price_per_hour_dero,
		 capacity_max_clients, protocol_version, bond_dero, status, version, last_seen, fail_count)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(node_id) DO UPDATE SET
		wg_pubkey=excluded.wg_pubkey, region=excluded.region, country=excluded.country,
		city=excluded.city, endpoint=excluded.endpoint,
		price_per_hour_dero=excluded.price_per_hour_dero,
		capacity_max_clients=excluded.capacity_max_clients,
		protocol_version=excluded.protocol_version, bond_dero=excluded.bond_dero,
		status=excluded.status, version=excluded.version,
		last_seen=excluded.last_seen, fail_count=excluded.fail_count`,
		n.NodeID, n.WGPubkey, n.Region, n.Country, n.City, n.Endpoint,
		n.PricePerHourDero, n.CapacityMaxClients, n.ProtocolVersion,
		n.BondDero, n.Status, n.Version, n.LastSeen.UTC().Format(time.RFC3339Nano), n.FailCount)
	return err
}

// GetNode fetches one node by id.
func (s *Store) GetNode(id string) (Node, error) {
	var n Node
	var lastSeen string
	err := s.db.QueryRow(`SELECT node_id, wg_pubkey, region, country, city, endpoint,
		price_per_hour_dero, capacity_max_clients, protocol_version, bond_dero,
		status, version, last_seen, fail_count FROM saved_nodes WHERE node_id=?`, id).
		Scan(&n.NodeID, &n.WGPubkey, &n.Region, &n.Country, &n.City, &n.Endpoint,
			&n.PricePerHourDero, &n.CapacityMaxClients, &n.ProtocolVersion,
			&n.BondDero, &n.Status, &n.Version, &lastSeen, &n.FailCount)
	if err != nil {
		return Node{}, err
	}
	n.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeen)
	return n, nil
}

// ListNodes returns all saved nodes ordered by id.
func (s *Store) ListNodes() ([]Node, error) {
	rows, err := s.db.Query(`SELECT node_id, wg_pubkey, region, country, city, endpoint,
		price_per_hour_dero, capacity_max_clients, protocol_version, bond_dero,
		status, version, last_seen, fail_count FROM saved_nodes ORDER BY node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		var lastSeen string
		if err := rows.Scan(&n.NodeID, &n.WGPubkey, &n.Region, &n.Country, &n.City,
			&n.Endpoint, &n.PricePerHourDero, &n.CapacityMaxClients, &n.ProtocolVersion,
			&n.BondDero, &n.Status, &n.Version, &lastSeen, &n.FailCount); err != nil {
			return nil, err
		}
		n.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeen)
		out = append(out, n)
	}
	return out, rows.Err()
}

// RecordLatency appends one probe sample and prunes samples older than 7 days.
func (s *Store) RecordLatency(nodeID string, d time.Duration) error {
	if _, err := s.db.Exec(`INSERT INTO latency_history(node_id, latency_ms) VALUES (?,?)`,
		nodeID, d.Milliseconds()); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM latency_history WHERE at < datetime('now','-7 days')`)
	return err
}

// LatencyHistory returns the most recent samples (newest first, up to limit).
func (s *Store) LatencyHistory(nodeID string, limit int) ([]time.Duration, []time.Time, error) {
	rows, err := s.db.Query(`SELECT latency_ms, at FROM latency_history
		WHERE node_id=? ORDER BY at DESC LIMIT ?`, nodeID, limit)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var ds []time.Duration
	var ts []time.Time
	for rows.Next() {
		var ms int64
		var at string
		if err := rows.Scan(&ms, &at); err != nil {
			return nil, nil, err
		}
		t, _ := time.Parse("2006-01-02T15:04:05.999Z07:00", at)
		if t.IsZero() {
			t, _ = time.Parse("2006-01-02 15:04:05", at)
		}
		ds = append(ds, time.Duration(ms)*time.Millisecond)
		ts = append(ts, t)
	}
	return ds, ts, rows.Err()
}

// AvgLatency returns the mean of the last limit samples.
func (s *Store) AvgLatency(nodeID string, limit int) (time.Duration, int, error) {
	var avg sql.NullFloat64
	var n int
	err := s.db.QueryRow(`SELECT AVG(latency_ms), COUNT(*) FROM
		(SELECT latency_ms FROM latency_history WHERE node_id=? ORDER BY at DESC LIMIT ?)`,
		nodeID, limit).Scan(&avg, &n)
	if err != nil {
		return 0, 0, err
	}
	if !avg.Valid {
		return 0, 0, nil
	}
	return time.Duration(avg.Float64) * time.Millisecond, n, nil
}

// SetTrust stores the local trust score [0,1] for a node.
func (s *Store) SetTrust(nodeID string, score float64, samples int) error {
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	_, err := s.db.Exec(`INSERT INTO local_trust(node_id, score, samples, updated_at)
		VALUES (?,?,?,strftime('%Y-%m-%dT%H:%M:%fZ','now'))
		ON CONFLICT(node_id) DO UPDATE SET score=excluded.score,
		samples=excluded.samples, updated_at=excluded.updated_at`,
		nodeID, score, samples)
	return err
}

// GetTrust returns the stored score, defaulting to 0.5/0 when unknown.
func (s *Store) GetTrust(nodeID string) (float64, int, error) {
	var score float64
	var samples int
	err := s.db.QueryRow(`SELECT score, samples FROM local_trust WHERE node_id=?`, nodeID).
		Scan(&score, &samples)
	if err == sql.ErrNoRows {
		return 0.5, 0, nil
	}
	return score, samples, err
}

// Connection records one tunnel session.
type Connection struct {
	ID        int64
	NodeID    string
	StartedAt time.Time
	EndedAt   sql.NullTime
	RxBytes   int64
	TxBytes   int64
}

// AddConnection opens a connection_history row.
func (s *Store) AddConnection(nodeID string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO connection_history(node_id) VALUES (?)`, nodeID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// EndConnection closes a row with final byte counters.
func (s *Store) EndConnection(id, rx, tx int64) error {
	_, err := s.db.Exec(`UPDATE connection_history SET
		ended_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'), rx_bytes=?, tx_bytes=? WHERE id=?`,
		rx, tx, id)
	return err
}

// ListConnections returns the most recent rows, newest first.
func (s *Store) ListConnections(limit int) ([]Connection, error) {
	rows, err := s.db.Query(`SELECT id, node_id, started_at, ended_at, rx_bytes, tx_bytes
		FROM connection_history ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Connection
	for rows.Next() {
		var c Connection
		var started, ended sql.NullString
		if err := rows.Scan(&c.ID, &c.NodeID, &started, &ended, &c.RxBytes, &c.TxBytes); err != nil {
			return nil, err
		}
		if started.Valid {
			c.StartedAt, _ = time.Parse("2006-01-02T15:04:05.999Z07:00", started.String)
		}
		if ended.Valid {
			if t, err := time.Parse("2006-01-02T15:04:05.999Z07:00", ended.String); err == nil {
				c.EndedAt = sql.NullTime{Time: t, Valid: true}
			}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Receipt records a settled payment.
type Receipt struct {
	ID        string
	NodeID    string
	SessionID string
	AmountDero float64
	TxID      string
	At        time.Time
}

// SaveReceipt stores a payment receipt.
func (s *Store) SaveReceipt(r Receipt) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO receipts(id, node_id, session_id, amount_dero, txid, at)
		VALUES (?,?,?,?,?,?)`, r.ID, r.NodeID, r.SessionID, r.AmountDero, r.TxID,
		r.At.UTC().Format(time.RFC3339Nano))
	return err
}

// ListReceipts returns receipts newest first.
func (s *Store) ListReceipts(limit int) ([]Receipt, error) {
	rows, err := s.db.Query(`SELECT id, node_id, session_id, amount_dero, txid, at
		FROM receipts ORDER BY at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Receipt
	for rows.Next() {
		var r Receipt
		var at string
		if err := rows.Scan(&r.ID, &r.NodeID, &r.SessionID, &r.AmountDero, &r.TxID, &at); err != nil {
			return nil, err
		}
		r.At, _ = time.Parse(time.RFC3339Nano, at)
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetSetting stores an opaque client setting.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key, value) VALUES (?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// GetSetting fetches a setting ("" when absent).
func (s *Store) GetSetting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// SetSession stores opaque session state (current node, circuit, etc.).
func (s *Store) SetSession(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO session_state(key, value) VALUES (?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// GetSession fetches session state ("" when absent).
func (s *Store) GetSession(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM session_state WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// ClearSession wipes resumed session state (used on clean disconnect).
func (s *Store) ClearSession() error {
	_, err := s.db.Exec(`DELETE FROM session_state`)
	return err
}
