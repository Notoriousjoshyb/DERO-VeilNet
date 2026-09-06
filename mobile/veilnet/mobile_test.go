package veilnet

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/dero-veilnet/veilnet/internal/app"
)

func decodeOK(t *testing.T, raw string) json.RawMessage {
	t.Helper()
	var env envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("bad envelope: %v (%s)", err, raw)
	}
	if !env.OK {
		t.Fatalf("ok:false: %s", env.Error)
	}
	return json.RawMessage(env.Data)
}

func decodeFail(t *testing.T, raw string) string {
	t.Helper()
	var env envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		t.Fatalf("bad envelope: %v (%s)", err, raw)
	}
	if env.OK {
		t.Fatalf("expected failure, got data %s", env.Data)
	}
	return env.Error
}

func withDemo(t *testing.T) {
	t.Helper()
	a, err := app.NewDemo()
	if err != nil {
		t.Skipf("demo app unavailable: %v", err)
	}
	t.Cleanup(func() { _ = a.Close(); resetForTest() })
	resetForTest()
	setBackendForTest(a)
	if out := Configure(`{"allow_paid":true}`); decodeOK(t, out) == nil {
		t.Fatal("configure failed")
	}
	setBackendForTest(a) // Configure reset the client; re-pin backend
}

// TestGomobileSafe asserts the exported API uses only gomobile-bindable
// types: params/returns limited to string (plus error-free signatures),
// exported structs limited to plain fields (no chan/func).
func TestGomobileSafe(t *testing.T) {
	ty := reflect.TypeOf
	_ = ty
	v := reflect.ValueOf(GetVersion)
	if v.Kind() != reflect.Func {
		t.Fatal("GetVersion not a func")
	}
	for _, fn := range []any{Configure, SelectNode, Start, Stop, Status, Diagnostics, GetVersion} {
		ft := reflect.TypeOf(fn)
		if ft.Kind() != reflect.Func {
			t.Fatalf("%v not a func", fn)
		}
		for i := 0; i < ft.NumIn(); i++ {
			if k := ft.In(i).Kind(); k != reflect.String {
				t.Fatalf("exported func in[%d] kind %v (want string)", i, k)
			}
		}
		for i := 0; i < ft.NumOut(); i++ {
			if k := ft.Out(i).Kind(); k != reflect.String {
				t.Fatalf("exported func out[%d] kind %v (want string)", i, k)
			}
		}
	}
	// No exported struct may carry chan/func fields.
	for _, st := range []any{envelope{}, mobileConfig{}} {
		rt := reflect.TypeOf(st)
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if !f.IsExported() {
				continue
			}
			switch f.Type.Kind() {
			case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Slice:
				if f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Uint8 {
					continue // []byte ok, though none exported
				}
				t.Fatalf("exported field %s.%s kind %v is not gomobile-safe", rt.Name(), f.Name, f.Type.Kind())
			}
		}
	}
}

func TestConfigureRejects(t *testing.T) {
	if msg := decodeFail(t, Configure(`{nope`)); msg == "" {
		t.Fatal("expected error")
	}
	if msg := decodeFail(t, Configure(`{"bogus_field":1}`)); msg == "" {
		t.Fatal("unknown field must be rejected")
	}
	if msg := decodeFail(t, Configure(`{"max_price_per_hour":-1}`)); msg == "" {
		t.Fatal("negative cap must be rejected")
	}
}

func TestMobileFlow(t *testing.T) {
	withDemo(t)

	sel := decodeOK(t, SelectNode(""))
	var node struct {
		NodeID string `json:"node_id"`
	}
	if err := json.Unmarshal(sel, &node); err != nil || node.NodeID == "" {
		t.Fatalf("select: %v %s", err, sel)
	}
	if msg := decodeFail(t, SelectNode("antarctica")); msg == "" {
		t.Fatal("unknown region must fail clearly")
	}

	started := decodeOK(t, Start(""))
	var q struct {
		NodeID string `json:"node_id"`
	}
	if err := json.Unmarshal(started, &q); err != nil || q.NodeID == "" {
		t.Fatalf("start: %v %s", err, started)
	}

	st := decodeOK(t, Status())
	var stv struct {
		NodeID string `json:"node_id"`
	}
	if err := json.Unmarshal(st, &stv); err != nil || stv.NodeID == "" {
		t.Fatalf("status: %v %s", err, st)
	}

	d := decodeOK(t, Diagnostics())
	if len(d) == 0 {
		t.Fatal("empty diagnostics")
	}

	decodeOK(t, Stop())
	var st2 struct {
		Connected bool `json:"connected"`
	}
	after := decodeOK(t, Status())
	if err := json.Unmarshal(after, &st2); err != nil {
		t.Fatal(err)
	}
	if st2.Connected {
		t.Fatal("still connected after Stop")
	}
}

func TestStartDeniedWhenPaidBlocked(t *testing.T) {
	a, err := app.NewDemo()
	if err != nil {
		t.Skipf("demo app unavailable: %v", err)
	}
	t.Cleanup(func() { _ = a.Close(); resetForTest() })
	resetForTest()
	setBackendForTest(a)
	decodeOK(t, Configure(`{"allow_paid":false}`))
	setBackendForTest(a)
	// Demo nodes are priced; with AllowPaid=false Start must refuse
	// rather than spend.
	if msg := decodeFail(t, Start("")); msg == "" {
		t.Fatal("paid connect without approval must be denied")
	}
}
