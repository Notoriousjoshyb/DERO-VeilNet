package reputation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// nodeInfo carries caller-supplied bond/uptime for scoring.
type nodeInfo struct {
	bond   float64
	uptime float64
	hasUp  bool
}

// Store is a local JSON-file reputation store. It is safe for
// concurrent use. Persistence is a single JSON document; writes are
// atomic (temp file + rename).
type Store struct {
	mu       sync.Mutex
	path     string
	evidence []Evidence
	// history counts local session outcomes per node.
	success map[string]int
	fail    map[string]int
	info    map[string]nodeInfo
}

// Open loads (or creates) the store at path. Empty path = in-memory only.
func Open(path string) (*Store, error) {
	s := &Store{info: map[string]nodeInfo{}, success: map[string]int{}, fail: map[string]int{}}
	if path != "" {
		s.path = path
		raw, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("reputation: open: %w", err)
			}
			return s, nil
		}
		if len(bytes.TrimSpace(raw)) > 0 {
			var disk struct {
				Evidence []Evidence     `json:"evidence"`
				Success  map[string]int `json:"success"`
				Fail     map[string]int `json:"fail"`
				Info     map[string]struct {
					Bond   float64 `json:"bond"`
					Uptime float64 `json:"uptime"`
					HasUp  bool    `json:"has_up"`
				} `json:"info"`
			}
			if err := json.Unmarshal(raw, &disk); err != nil {
				return nil, fmt.Errorf("reputation: corrupt store: %w", err)
			}
			s.evidence = disk.Evidence
			if disk.Success != nil {
				s.success = disk.Success
			}
			if disk.Fail != nil {
				s.fail = disk.Fail
			}
			for id, ni := range disk.Info {
				s.info[id] = nodeInfo{bond: ni.Bond, uptime: ni.Uptime, hasUp: ni.HasUp}
			}
		}
	}
	return s, nil
}

// saveLocked persists atomically. Callers hold mu.
func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	disk := map[string]any{
		"evidence": s.evidence,
		"success":  s.success,
		"fail":     s.fail,
	}
	infos := map[string]any{}
	for id, ni := range s.info {
		infos[id] = map[string]any{"bond": ni.bond, "uptime": ni.uptime, "has_up": ni.hasUp}
	}
	disk["info"] = infos
	raw, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Add verifies e (reporter sig + offline slash proof) and appends it.
// Adversarial or malformed evidence is rejected, never stored.
func (s *Store) Add(e Evidence) error {
	if err := e.Verify(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evidence = append(s.evidence, e)
	return s.saveLocked()
}

// RecordSession logs one local session outcome for history scoring.
func (s *Store) RecordSession(nodeID string, ok bool) error {
	if nodeID == "" {
		return errors.New("reputation: empty node_id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok {
		s.success[nodeID]++
	} else {
		s.fail[nodeID]++
	}
	return s.saveLocked()
}

// SetNodeInfo records bond/uptime observations for scoring.
func (s *Store) SetNodeInfo(nodeID string, bondDERO, uptime float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.info[nodeID] = nodeInfo{bond: bondDERO, uptime: uptime, hasUp: true}
	_ = s.saveLocked()
}

// EvidenceFor returns verified-stored evidence for a node (copy).
func (s *Store) EvidenceFor(nodeID string) []Evidence {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Evidence
	for _, e := range s.evidence {
		if e.NodeID == nodeID {
			out = append(out, e)
		}
	}
	return out
}

// Slashed reports whether verified SLASHABLE evidence exists locally.
func (s *Store) Slashed(nodeID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.evidence {
		if e.NodeID == nodeID && IsSlashable(e.Kind) {
			return true
		}
	}
	return false
}

// History returns the 0..1 local reliability for nodeID
// (UnknownHistory when no sessions recorded).
func (s *Store) History(nodeID string) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	ok, bad := s.success[nodeID], s.fail[nodeID]
	if ok+bad == 0 {
		return UnknownHistory
	}
	return float64(ok) / float64(ok+bad)
}

// ReputationScore implements Scorer: Score() with store-local inputs.
func (s *Store) ReputationScore(nodeID string) float64 {
	s.mu.Lock()
	ni := s.info[nodeID]
	ok, bad := s.success[nodeID], s.fail[nodeID]
	slashed := false
	for _, e := range s.evidence {
		if e.NodeID == nodeID && IsSlashable(e.Kind) {
			slashed = true
			break
		}
	}
	s.mu.Unlock()
	hist := UnknownHistory
	if ok+bad > 0 {
		hist = float64(ok) / float64(ok+bad)
	}
	up := 0.5
	if ni.hasUp {
		up = ni.uptime
	}
	return Score(ScoreInput{BondDERO: ni.bond, Uptime: up, History: hist, Slashed: slashed})
}

// Summary builds a signed ADVISORY gossip summary for nodeID.
func (s *Store) Summary(nodeID string, priv ed25519.PrivateKey) (Advisory, error) {
	s.mu.Lock()
	ok, bad := s.success[nodeID], s.fail[nodeID]
	ni := s.info[nodeID]
	s.mu.Unlock()
	total := ok + bad
	up := 0.5
	if ni.hasUp {
		up = ni.uptime
	} else if total > 0 {
		up = float64(ok) / float64(total)
	}
	a := Advisory{
		NodeID:  nodeID,
		Uptime:  clip01(up),
		Samples: total,
		At:      time.Now().UTC().Truncate(time.Second),
	}
	if err := a.Sign(priv); err != nil {
		return Advisory{}, err
	}
	return a, nil
}
