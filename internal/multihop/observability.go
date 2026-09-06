// Per-node observability: exactly what each hop of a VeilNet circuit can
// and cannot see. This is normative for user-facing copy: the UI and docs
// must describe exposure in these terms and must never claim a hop learns
// less than stated here.
//
//	TWO-HOP circuit  client -> ENTRY -> EXIT -> destination
//
//	ENTRY sees:
//	  - client real IP address (it terminates the client's WireGuard segment)
//	  - that the client is using VeilNet, timing + volume of encrypted cells
//	  - the EXIT node's identity/endpoint (it forwards chained cells there)
//	  - NOT the final destination (host, path, query) nor payload content:
//	    the inner layer is encrypted to the EXIT.
//	EXIT sees:
//	  - the ENTRY node's identity (its WireGuard peer), timing + volume
//	  - the final destination host and plaintext it sends/receives there
//	    (e.g. TLS SNI/IP for HTTPS; full content only on unencrypted protocols)
//	  - NOT the client's real IP: the outer source is the ENTRY node.
//	EITHER hop, if malicious or compelled, can log what it sees; colluding
//	ENTRY+EXIT (or a global observer watching both segments) can correlate
//	timing/volume to link client and destination. See docs/THREAT_MODEL.md.
//
//	THREE-HOP circuit  client -> ENTRY -> MIDDLE -> EXIT -> destination
//
//	ENTRY sees exactly what a 2-hop entry sees: the client IP, VeilNet use,
//	timing + volume, and the MIDDLE identity — never the destination.
//	MIDDLE sees neither end: its peers are ENTRY and EXIT only; it learns
//	timing + volume of doubly-encrypted cells and nothing else. It knows
//	neither WHO (client IP stays behind the entry) nor WHERE (destination
//	stays inside the exit layer).
//	EXIT sees exactly what a 2-hop exit sees: the destination and whatever
//	plaintext the app protocol exposes — never the client IP (outer source
//	is the MIDDLE node).
//	Any single malicious hop learns at most one end; linking client to
//	destination needs ENTRY+EXIT collusion (or a global observer), exactly
//	as in the 2-hop case, with the middle adding one more independent
//	party that must collude. See docs/THREAT_MODEL.md.
//
//	SINGLE-HOP circuit  client -> NODE -> destination
//
//	The single node sees BOTH the client IP and the destination: it offers
//	no separation. Used only as an explicit fallback when fewer than two
//	suitable nodes exist; the UI must badge single-hop distinctly from the
//	default 2-hop circuit.
package multihop

// Exposure describes what one hop position learns about the flow.
type Exposure struct {
	Position         string // "entry" | "middle" | "exit" | "single"
	SeesClientIP     bool
	SeesDestination  bool
	SeesPayloadPlain bool // plaintext only if the app protocol itself is unencrypted
	Summary          string
}

// EntryExposure returns the documented ENTRY-hop visibility.
func EntryExposure() Exposure {
	return Exposure{
		Position:         "entry",
		SeesClientIP:     true,
		SeesDestination:  false,
		SeesPayloadPlain: false,
		Summary:          "entry knows WHO is connected (client IP) but not WHERE they go (destination hidden by inner layer to exit)",
	}
}

// ExitExposure returns the documented EXIT-hop visibility.
func ExitExposure() Exposure {
	return Exposure{
		Position:         "exit",
		SeesClientIP:     false,
		SeesDestination:  true,
		SeesPayloadPlain: false,
		Summary:          "exit knows WHERE traffic goes (destination) but not WHO sent it (client IP hidden behind entry); sees only whatever plaintext the app protocol itself exposes",
	}
}

// SingleHopExposure returns the documented fallback visibility: the lone
// node sees both ends.
func SingleHopExposure() Exposure {
	return Exposure{
		Position:         "single",
		SeesClientIP:     true,
		SeesDestination:  true,
		SeesPayloadPlain: false,
		Summary:          "single-hop fallback: the lone node sees both client IP and destination (no separation); UI must badge this distinctly",
	}
}

// MiddleExposure returns the documented MIDDLE-hop visibility (3-hop
// circuits only): the middle learns neither end.
func MiddleExposure() Exposure {
	return Exposure{
		Position:         "middle",
		SeesClientIP:     false,
		SeesDestination:  false,
		SeesPayloadPlain: false,
		Summary:          "middle knows NEITHER end: peers are entry and exit only, cells are doubly encrypted; timing + volume only",
	}
}

// Exposures returns the per-hop visibility for a hop count (1-3) in path
// order. It is the machine-readable form of the comment block above; UI
// copy must stay consistent with it.
func Exposures(hops int) []Exposure {
	switch hops {
	case 1:
		return []Exposure{SingleHopExposure()}
	case 3:
		return []Exposure{EntryExposure(), MiddleExposure(), ExitExposure()}
	default:
		return []Exposure{EntryExposure(), ExitExposure()}
	}
}
