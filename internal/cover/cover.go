// Package cover implements measurable traffic shaping: padding and
// constant-rate cover fill.
//
// WHAT THIS DEFENDS AGAINST, honestly:
//
//   - Padding hides exact packet SIZES from an observer who can see the
//     encrypted stream. It does not hide timing.
//   - Constant-rate hides both size and TIMING for as long as the tunnel
//     keeps up with the configured rate. Bursts above the rate still
//     queue, and a long queue is itself observable.
//
// WHAT IT DOES NOT DEFEND AGAINST:
//
//   - A global passive adversary who watches both ends. That is out of
//     scope for VeilNet and always will be; see docs/THREAT_MODEL.md.
//   - Traffic confirmation over long observation windows.
//   - Anything above the tunnel: application behaviour, DNS choices,
//     login patterns.
//
// Every mode reports exactly what it cost (Stats), because the roadmap
// rule for this work is "measured, never oversold". Shaping is OFF by
// default: it trades real bandwidth for a narrow, specific gain, and the
// user makes that trade explicitly.
package cover

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Mode selects the shaping strategy.
type Mode string

// Shaping modes.
const (
	// OFF passes packets through untouched. Default.
	OFF Mode = "OFF"
	// PAD rounds each packet up to the next bucket size. Cheap; hides
	// sizes only.
	PAD Mode = "PAD"
	// CONSTANT emits a fixed-size cell on a fixed interval, filling idle
	// slots with cover traffic. Expensive; hides size and timing.
	CONSTANT Mode = "CONSTANT"
)

// DefaultBuckets are the padding sizes, chosen to sit under a 1420-byte
// WireGuard payload MTU so a padded packet never fragments.
var DefaultBuckets = []int{128, 256, 512, 1024, 1420}

// Config describes a shaper. The zero value is a valid OFF shaper.
type Config struct {
	Mode Mode
	// Buckets are the PAD target sizes, ascending. Empty uses
	// DefaultBuckets.
	Buckets []int
	// CellSize is the CONSTANT cell payload size in bytes.
	CellSize int
	// Interval is the CONSTANT emission period.
	Interval time.Duration
	// MaxOverhead caps wasted bandwidth as a ratio of real bytes
	// (0.5 = at most 50% cover). Zero means no cap. CONSTANT stops
	// emitting idle cover once the cap is hit, so shaping degrades to
	// "no worse than unshaped" rather than eating the link.
	MaxOverhead float64
}

// Validate rejects a config that cannot be honoured.
func (c Config) Validate() error {
	switch c.Mode {
	case "", OFF:
		return nil
	case PAD:
		for i, b := range c.Buckets {
			if b <= 0 {
				return fmt.Errorf("cover: bucket %d must be > 0", i)
			}
			if i > 0 && b <= c.Buckets[i-1] {
				return errors.New("cover: buckets must be ascending and distinct")
			}
		}
		return nil
	case CONSTANT:
		if c.CellSize <= 0 {
			return errors.New("cover: CONSTANT needs a cell size > 0")
		}
		if c.Interval <= 0 {
			return errors.New("cover: CONSTANT needs an interval > 0")
		}
		if c.MaxOverhead < 0 {
			return errors.New("cover: MaxOverhead must be >= 0")
		}
		return nil
	default:
		return fmt.Errorf("cover: unknown mode %q", c.Mode)
	}
}

// Stats is the measured cost of shaping. RealBytes is payload the user
// actually sent; PadBytes and CoverBytes are what shaping added.
type Stats struct {
	Mode        Mode
	Packets     int64
	RealBytes   int64
	PadBytes    int64
	CoverBytes  int64
	CoverCells  int64
	DroppedOver int64 // cover cells skipped because MaxOverhead was hit
}

// TotalBytes is everything put on the wire.
func (s Stats) TotalBytes() int64 { return s.RealBytes + s.PadBytes + s.CoverBytes }

// Overhead is added bytes as a ratio of real bytes. Zero real bytes with
// cover sent reports +Inf, which is honest: it is all overhead.
func (s Stats) Overhead() float64 {
	added := float64(s.PadBytes + s.CoverBytes)
	if s.RealBytes == 0 {
		if added == 0 {
			return 0
		}
		return inf()
	}
	return added / float64(s.RealBytes)
}

func inf() float64 {
	var zero float64
	return 1 / zero
}

// Emission is one shaped unit handed to the caller for transmission.
type Emission struct {
	// PayloadLen is the real bytes carried (0 for a pure cover cell).
	PayloadLen int
	// WireLen is what actually goes on the wire.
	WireLen int
	// Cover is true when this unit carries no user data.
	Cover bool
}

// Shaper applies a Config. It is safe for concurrent use.
//
// The shaper computes sizes; it does not own a socket. Callers feed it
// packet lengths and transmit what it returns. That keeps it fully
// testable and keeps the data path in one place (internal/tunnel).
type Shaper struct {
	mu      sync.Mutex
	cfg     Config
	buckets []int
	stats   Stats
	// pending is real payload waiting for the next CONSTANT cell.
	pending []int
	lastIdle time.Time
}

// New builds a Shaper. An invalid config is an error, never a silent
// downgrade to OFF: the user asked for protection and must be told it
// was not applied.
func New(cfg Config) (*Shaper, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.Mode == "" {
		cfg.Mode = OFF
	}
	buckets := cfg.Buckets
	if cfg.Mode == PAD && len(buckets) == 0 {
		buckets = append([]int(nil), DefaultBuckets...)
	}
	sort.Ints(buckets)
	return &Shaper{cfg: cfg, buckets: buckets, stats: Stats{Mode: cfg.Mode}}, nil
}

// Mode reports the active mode.
func (s *Shaper) Mode() Mode {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.Mode
}

// Stats returns a snapshot of measured cost.
func (s *Shaper) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

// Send shapes one outbound packet of payloadLen bytes.
//
// OFF and PAD return one Emission immediately. CONSTANT queues the
// payload and returns nil: the packet leaves on the next Tick, which is
// what makes the timing uniform.
func (s *Shaper) Send(payloadLen int) *Emission {
	if payloadLen < 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.cfg.Mode {
	case CONSTANT:
		s.pending = append(s.pending, payloadLen)
		return nil
	case PAD:
		wire := s.padTo(payloadLen)
		s.stats.Packets++
		s.stats.RealBytes += int64(payloadLen)
		s.stats.PadBytes += int64(wire - payloadLen)
		return &Emission{PayloadLen: payloadLen, WireLen: wire}
	default: // OFF
		s.stats.Packets++
		s.stats.RealBytes += int64(payloadLen)
		return &Emission{PayloadLen: payloadLen, WireLen: payloadLen}
	}
}

// Tick produces the CONSTANT-mode emission due at time now. It returns
// nil in every other mode, and nil when the overhead cap has been hit
// with nothing real to send.
func (s *Shaper) Tick(now time.Time) *Emission {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Mode != CONSTANT {
		return nil
	}

	cell := s.cfg.CellSize
	if len(s.pending) > 0 {
		payload := s.pending[0]
		s.pending = s.pending[1:]
		if payload > cell {
			// Oversized payloads are not silently truncated: they ride
			// in their own larger cell, and the size leak is recorded
			// as zero padding rather than hidden.
			s.stats.Packets++
			s.stats.RealBytes += int64(payload)
			return &Emission{PayloadLen: payload, WireLen: payload}
		}
		s.stats.Packets++
		s.stats.RealBytes += int64(payload)
		s.stats.PadBytes += int64(cell - payload)
		return &Emission{PayloadLen: payload, WireLen: cell}
	}

	// Idle slot: send cover, unless that would break the overhead cap.
	if s.cfg.MaxOverhead > 0 {
		added := float64(s.stats.PadBytes+s.stats.CoverBytes+int64(cell))
		real := float64(s.stats.RealBytes)
		if real == 0 || added/real > s.cfg.MaxOverhead {
			s.stats.DroppedOver++
			return nil
		}
	}
	s.lastIdle = now
	s.stats.CoverCells++
	s.stats.CoverBytes += int64(cell)
	return &Emission{WireLen: cell, Cover: true}
}

// Pending reports how many real packets are queued for the next cells.
// A growing queue means the configured rate is too slow for the traffic,
// which the UI should surface rather than hide.
func (s *Shaper) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// padTo rounds n up to the next bucket. Anything larger than the biggest
// bucket is left alone: growing it further would fragment.
func (s *Shaper) padTo(n int) int {
	for _, b := range s.buckets {
		if n <= b {
			return b
		}
	}
	return n
}
