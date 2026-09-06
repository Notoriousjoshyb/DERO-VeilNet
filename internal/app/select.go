package app

import (
	"errors"
	"sort"

	"github.com/dero-veilnet/veilnet/internal/config"
)

// AutoSelect picks the best node under the configured policy (or policy
// override). Scoring blends latency, load, availability, price, and local
// history. Unavailable nodes (non-active status, repeated failures) are
// excluded, never preferred.
func (a *App) AutoSelect() (NodeInfo, error) {
	a.mu.RLock()
	policy := a.cfg.Network.SelectPolicy
	region := a.cfg.Region
	a.mu.RUnlock()
	return a.Select(policy, region)
}

// Select scores candidates under policy with a SPECIFIC_REGION filter.
func (a *App) Select(policy, region string) (NodeInfo, error) {
	if policy == "" {
		policy = config.SelectFastest
	}
	nodes, err := a.ListNodes()
	if err != nil {
		return NodeInfo{}, err
	}
	type scored struct {
		n NodeInfo
		s float64
	}
	var cands []scored
	for _, n := range nodes {
		if n.Status != "" && n.Status != "active" {
			continue
		}
		if n.FailCount >= 5 {
			continue
		}
		if policy == config.SelectSpecificReg && region != "" && n.Region != region {
			continue
		}
		cands = append(cands, scored{n: n, s: score(policy, n, nodes)})
	}
	if len(cands) == 0 {
		return NodeInfo{}, errors.New("no suitable nodes available")
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].s > cands[j].s })
	return cands[0].n, nil
}

// score blends normalized latency (lower better), load (lower better),
// price (lower better), bond/trust/history (higher better).
func score(policy string, n NodeInfo, all []NodeInfo) float64 {
	var wLat, wLoad, wPrice, wTrust float64
	switch policy {
	case config.SelectLowestLoad:
		wLat, wLoad, wPrice, wTrust = 0.25, 0.5, 0.1, 0.15
	case config.SelectLowestPrice:
		wLat, wLoad, wPrice, wTrust = 0.25, 0.15, 0.5, 0.1
	case config.SelectPrivacy:
		wLat, wLoad, wPrice, wTrust = 0.15, 0.15, 0.05, 0.65
	case config.SelectSpecificReg:
		wLat, wLoad, wPrice, wTrust = 0.4, 0.2, 0.15, 0.25
	default: // FASTEST
		wLat, wLoad, wPrice, wTrust = 0.55, 0.15, 0.1, 0.2
	}

	maxLat, maxPrice := 1.0, 1.0
	for _, o := range all {
		if o.LatencyMs > 0 && float64(o.LatencyMs) > maxLat {
			maxLat = float64(o.LatencyMs)
		}
		if o.PricePerHourDero > maxPrice {
			maxPrice = o.PricePerHourDero
		}
	}
	lat := maxLat
	if n.LatencyMs > 0 {
		lat = float64(n.LatencyMs)
	} else if n.LatencyMs < 0 {
		lat = maxLat // unknown latency scores worst, never blocks
	}
	latScore := 1 - lat/maxLat
	if maxLat <= 1 {
		latScore = 0.5
	}
	loadScore := 1 - clamp01(n.Load)
	priceScore := 1 - n.PricePerHourDero/maxPrice
	hist := clamp01(n.Trust)*0.7 + clamp01(n.BondDero/100)*0.3
	return wLat*latScore + wLoad*loadScore + wPrice*priceScore + wTrust*hist
}

func clamp01(f float64) float64 {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return f
}
