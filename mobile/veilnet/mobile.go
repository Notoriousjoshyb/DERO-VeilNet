package veilnet

import (
	"encoding/json"
	"sync"

	sdk "github.com/dero-veilnet/veilnet/sdk/veilnet"
	"github.com/dero-veilnet/veilnet/internal/app"
)

// backend is the unexported control-plane seam. Production wiring wraps
// *app.App via newAppBackend; tests inject fakes. Unexported so gomobile
// never tries to bind it.
type backend interface {
	sdk.Backend
}

// state is the process-wide singleton. A singleton (rather than an
// exported handle type) keeps the exported API to plain functions on
// strings, which every gomobile target supports.
var state = struct {
	sync.Mutex
	client *sdk.Client
	app    *app.App
	config mobileConfig
}{
	config: defaultConfig(),
}

type mobileConfig struct {
	Region          string  `json:"region"`
	MaxPricePerHour float64 `json:"max_price_per_hour"`
	QuoteHours      float64 `json:"quote_hours"`
	// AllowPaid preseeds the approval hook: true approves quotes up to
	// MaxPricePerHour (still explicit — the host confirms via
	// PendingQuote before Start spends anything); false denies all paid
	// connects. The device UI must surface the quote.
	AllowPaid bool `json:"allow_paid"`
}

func defaultConfig() mobileConfig {
	return mobileConfig{QuoteHours: 1, AllowPaid: false}
}

// envelope is the single JSON shape every exported function returns.
type envelope struct {
	OK    bool   `json:"ok"`
	Data  string `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

func ok(data any) string {
	raw, err := json.Marshal(data)
	if err != nil {
		return fail("encode: " + err.Error())
	}
	out, _ := json.Marshal(envelope{OK: true, Data: string(raw)})
	return string(out)
}

func fail(msg string) string {
	out, _ := json.Marshal(envelope{Error: msg})
	return string(out)
}

// ensureClient builds the SDK client over the configured backend.
// Callers hold state.Lock.
func ensureClientLocked() error {
	if state.client != nil {
		return nil
	}
	cfg := state.config
	hours := cfg.QuoteHours
	if hours <= 0 {
		hours = 1
	}
	var be backend
	if state.app != nil {
		be = &sdk.AppBackend{App: state.app}
	} else {
		a, err := app.NewDemo()
		if err != nil {
			return err
		}
		state.app = a
		be = &sdk.AppBackend{App: a}
	}
	approve := func(q sdk.Quote) bool {
		if q.AmountDERO <= 0 {
			return true
		}
		if !cfg.AllowPaid {
			return false
		}
		if cfg.MaxPricePerHour > 0 && q.AmountDERO > cfg.MaxPricePerHour*hours {
			return false
		}
		return true
	}
	c, err := sdk.New(sdk.Config{
		Region:          cfg.Region,
		MaxPricePerHour: cfg.MaxPricePerHour,
		QuoteHours:      hours,
		Approve:         approve,
	}, be)
	if err != nil {
		return err
	}
	state.client = c
	return nil
}

// setBackendForTest swaps the app backend (Go tests only; unexported so
// gomobile ignores it).
func setBackendForTest(a *app.App) {
	state.Lock()
	defer state.Unlock()
	if state.app != nil && state.app != a {
		_ = state.app.Close()
	}
	state.app = a
	state.client = nil
}

// resetForTest drops client state (Go tests only).
func resetForTest() {
	state.Lock()
	defer state.Unlock()
	state.client = nil
	state.config = defaultConfig()
}
