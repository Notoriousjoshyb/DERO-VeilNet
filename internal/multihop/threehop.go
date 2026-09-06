package multihop

import (
	"errors"
	"sync/atomic"
	"time"
)

// ErrThreeHopDisabled is returned whenever a 3-hop circuit is requested
// while the flag is off. The 3-hop path is architecture-present but
// disabled: callers must handle this error explicitly (usually by
// continuing on the verified 2-hop circuit). A 2-hop circuit is NEVER
// relabelled as 3-hop to satisfy a caller.
var ErrThreeHopDisabled = errors.New("multihop: 3-hop circuits are disabled in this build (2-hop maximum)")

// threeHopEnabled gates the 3-hop builder. Default false. Flipped only by
// SetThreeHopEnabled from an explicit user/devnet opt-in; there is no
// config-file silent enable.
var threeHopEnabled atomic.Bool

// SetThreeHopEnabled opts into (or out of) the experimental 3-hop path.
// Reserved for devnet/testing; production callers leave the default off.
func SetThreeHopEnabled(on bool) { threeHopEnabled.Store(on) }

// ThreeHopEnabled reports the flag state.
func ThreeHopEnabled() bool { return threeHopEnabled.Load() }

// ThreeHopCircuit is the architecture for a future ENTRY -> MIDDLE -> EXIT
// path. Present so route construction, verification, and rotation logic
// have a place to land; construction is refused while the flag is off.
type ThreeHopCircuit struct {
	ID        string
	Entry     NodeInfo
	Middle    NodeInfo
	Exit      NodeInfo
	CreatedAt time.Time
}

// BuildThreeHop validates the three nodes and — only when the flag is
// enabled — returns the middle-inclusive circuit. While disabled it returns
// (nil, ErrThreeHopDisabled) with no fallback substitution. New callers
// prefer BuildThreeHopCircuit (or BuildRoute), which need no flag.
func BuildThreeHop(entry, middle, exit NodeInfo) (*ThreeHopCircuit, error) {
	if !threeHopEnabled.Load() {
		return nil, ErrThreeHopDisabled
	}
	if err := entry.Validate(); err != nil {
		return nil, err
	}
	if err := middle.Validate(); err != nil {
		return nil, err
	}
	if err := exit.Validate(); err != nil {
		return nil, err
	}
	if err := checkDistinct([]NodeInfo{entry, middle, exit}); err != nil {
		return nil, err
	}
	return &ThreeHopCircuit{
		ID:        newID(),
		Entry:     entry,
		Middle:    middle,
		Exit:      exit,
		CreatedAt: time.Now().UTC(),
	}, nil
}
