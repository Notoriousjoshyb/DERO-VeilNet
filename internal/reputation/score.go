package reputation

// Scoring weights (documented, fixed). Score is 0..1, higher is better.
//
//	score = clamp01(wBond*bondN + wUptime*uptime + wHistory*history)
//	if any verified SLASHABLE evidence exists for the node: score = 0.
//
//	bondN   = min(bondDERO / BondFullDERO, 1) — bonded stake signal.
//	uptime  = caller-supplied 0..1 availability (clipped).
//	history = local past-session reliability 0..1 (default 0.5 unknown).
//
// A slash zeroes the LOCAL score only. It is never broadcast as a kill:
// gossip carries signed ADVISORY summaries, and each client applies its
// own weights. Omitting a node locally is not a global verdict.
const (
	WBond    = 0.30
	WUptime  = 0.30
	WHist    = 0.40
	// BondFullDERO is the bond at which the bond term saturates to 1.
	BondFullDERO = 100.0
	// UnknownHistory is the history term for nodes with no local past.
	UnknownHistory = 0.5
)

func clip01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// ScoreInput is everything Score needs; callers source bond/uptime from
// the registry and local observations, history/slash from the Store.
type ScoreInput struct {
	BondDERO float64
	Uptime   float64 // 0..1
	History  float64 // 0..1
	Slashed  bool    // verified local SLASHABLE evidence present
}

// Score computes the 0..1 reputation score. Slashed => 0, always.
func Score(in ScoreInput) float64 {
	if in.Slashed {
		return 0
	}
	bondN := clip01(in.BondDERO / BondFullDERO)
	return clip01(WBond*bondN + WUptime*clip01(in.Uptime) + WHist*clip01(in.History))
}

// Scorer is the weights hook consumed by selection: anything that can
// score a node_id. *Store implements it.
type Scorer interface {
	ReputationScore(nodeID string) float64
}

// HistoryScore adapts a Scorer to the registry History shape
// (Score(nodeID) float64) WITHOUT editing the registry package:
//
//	import "github.com/dero-veilnet/veilnet/internal/registry"
//	criteria := registry.Criteria{History: reputation.HistoryScore(store)}
//
// where store is a *Store (optionally pre-tuned with bond/uptime via
// [Store.SetNodeInfo]). If s is nil, Score returns UnknownHistory.
func HistoryScore(s Scorer) HistoryLike {
	return HistoryLike{Scorer: s}
}

// HistoryLike has exactly the method set registry.History requires
// (Score(string) float64), kept as a local type so reputation does not
// import registry and no import cycle is possible.
type HistoryLike struct {
	Scorer Scorer
}

// Score implements the registry History interface shape.
func (h HistoryLike) Score(nodeID string) float64 {
	if h.Scorer == nil {
		return UnknownHistory
	}
	return clip01(h.Scorer.ReputationScore(nodeID))
}
