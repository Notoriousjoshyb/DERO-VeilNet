package cover

import (
	"math"
	"testing"
	"time"
)

func TestOffIsPassthrough(t *testing.T) {
	s, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Mode() != OFF {
		t.Fatalf("mode = %q, want OFF by default", s.Mode())
	}
	e := s.Send(300)
	if e == nil || e.WireLen != 300 || e.Cover {
		t.Fatalf("emission = %+v, want untouched 300 bytes", e)
	}
	st := s.Stats()
	if st.PadBytes != 0 || st.CoverBytes != 0 {
		t.Fatalf("OFF must add nothing, got %+v", st)
	}
	if st.Overhead() != 0 {
		t.Fatalf("overhead = %v, want 0", st.Overhead())
	}
}

func TestPadRoundsToBuckets(t *testing.T) {
	s, err := New(Config{Mode: PAD, Buckets: []int{100, 500, 1000}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ in, want int }{
		{1, 100}, {100, 100}, {101, 500}, {500, 500}, {900, 1000},
		{1500, 1500}, // above the top bucket: left alone, never fragmented
	}
	for _, c := range cases {
		e := s.Send(c.in)
		if e == nil || e.WireLen != c.want {
			t.Fatalf("Send(%d) wire = %v, want %d", c.in, e, c.want)
		}
	}
	st := s.Stats()
	if st.PadBytes == 0 {
		t.Fatal("padding must be measured, not hidden")
	}
	if st.TotalBytes() != st.RealBytes+st.PadBytes {
		t.Fatalf("total %d != real %d + pad %d", st.TotalBytes(), st.RealBytes, st.PadBytes)
	}
}

func TestConstantEmitsUniformCells(t *testing.T) {
	s, err := New(Config{Mode: CONSTANT, CellSize: 512, Interval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	// A real packet queues rather than leaving immediately: that is what
	// makes the timing uniform.
	if e := s.Send(200); e != nil {
		t.Fatalf("CONSTANT must queue, got immediate %+v", e)
	}
	if s.Pending() != 1 {
		t.Fatalf("pending = %d, want 1", s.Pending())
	}

	now := time.Now()
	real := s.Tick(now)
	if real == nil || real.Cover || real.WireLen != 512 || real.PayloadLen != 200 {
		t.Fatalf("first tick = %+v, want a 512-byte cell carrying 200", real)
	}
	cover := s.Tick(now.Add(10 * time.Millisecond))
	if cover == nil || !cover.Cover || cover.WireLen != 512 {
		t.Fatalf("idle tick = %+v, want a 512-byte cover cell", cover)
	}
	st := s.Stats()
	if st.CoverCells != 1 || st.CoverBytes != 512 {
		t.Fatalf("cover accounting = %+v", st)
	}
}

// Oversized payloads must not be silently truncated. They ride in a
// bigger cell and the size leak shows up as zero padding.
func TestConstantDoesNotTruncateOversizedPayloads(t *testing.T) {
	s, _ := New(Config{Mode: CONSTANT, CellSize: 256, Interval: time.Millisecond})
	s.Send(1000)
	e := s.Tick(time.Now())
	if e == nil || e.PayloadLen != 1000 || e.WireLen != 1000 {
		t.Fatalf("emission = %+v, want the full 1000 bytes carried", e)
	}
}

// The overhead cap stops cover traffic eating the link.
func TestMaxOverheadCapsCoverTraffic(t *testing.T) {
	s, _ := New(Config{
		Mode: CONSTANT, CellSize: 100, Interval: time.Millisecond, MaxOverhead: 0.5,
	})
	s.Send(1000)
	now := time.Now()
	if e := s.Tick(now); e == nil {
		t.Fatal("queued payload must be emitted")
	}
	// 1000 real bytes: at most 500 bytes of cover, i.e. 5 cells.
	sent := 0
	for i := 0; i < 50; i++ {
		if e := s.Tick(now.Add(time.Duration(i) * time.Millisecond)); e != nil && e.Cover {
			sent++
		}
	}
	st := s.Stats()
	if st.Overhead() > 0.5+1e-9 {
		t.Fatalf("overhead %.3f exceeded the 0.5 cap", st.Overhead())
	}
	if st.DroppedOver == 0 {
		t.Fatal("skipped cover cells must be counted, not hidden")
	}
	if sent == 0 {
		t.Fatal("some cover should still be sent under the cap")
	}
}

// All-cover with no real traffic is reported as infinite overhead, which
// is the honest number, not a hidden zero.
func TestOverheadWithNoRealTrafficIsInfinite(t *testing.T) {
	st := Stats{CoverBytes: 100}
	if !math.IsInf(st.Overhead(), 1) {
		t.Fatalf("overhead = %v, want +Inf", st.Overhead())
	}
}

// A bad config is an error, never a silent downgrade to OFF: the user
// asked for protection and must be told it was not applied.
func TestInvalidConfigIsRefused(t *testing.T) {
	bad := []Config{
		{Mode: "SOMETHING"},
		{Mode: CONSTANT},
		{Mode: CONSTANT, CellSize: 100},
		{Mode: CONSTANT, CellSize: 100, Interval: time.Millisecond, MaxOverhead: -1},
		{Mode: PAD, Buckets: []int{100, 100}},
		{Mode: PAD, Buckets: []int{0}},
	}
	for i, c := range bad {
		if _, err := New(c); err == nil {
			t.Fatalf("config %d (%+v) must be refused", i, c)
		}
	}
}
