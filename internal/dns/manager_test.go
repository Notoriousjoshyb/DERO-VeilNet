package dns

import (
	"strings"
	"sync"
	"testing"

	"github.com/dero-veilnet/veilnet/internal/events"
)

type fakeRunner struct {
	mu    sync.Mutex
	calls []string
	// effective fakes the Get-DnsClientServerAddress output.
	effective string
}

func (f *fakeRunner) Run(name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "Get-DnsClientServerAddress"):
		return f.effective, nil
	case strings.Contains(joined, "show dns"):
		return "DNS servers: 192.168.1.1\n", nil
	}
	return "", nil
}

func (f *fakeRunner) joined() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, "\n")
}

func TestApplyAndRestore(t *testing.T) {
	fr := &fakeRunner{effective: "10.7.0.1\n"}
	m := New(fr, "veilnet", WithStateDir(t.TempDir()))
	got := make(chan any, 2)
	events.Subscribe(events.DNS_CHANGED, got)

	if err := m.Apply(VEILNET, []string{"10.7.0.1"}); err != nil {
		t.Fatal(err)
	}
	if m.Mode() != VEILNET {
		t.Fatalf("mode = %s", m.Mode())
	}
	select {
	case <-got:
	default:
		t.Fatal("missing DNS_CHANGED event")
	}
	log := fr.joined()
	for _, want := range []string{
		`set dns`, "10.7.0.1",
		"Add-DnsClientNrptRule", `-Namespace "."`,
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("missing %q in:\n%s", want, log)
		}
	}

	if err := m.Restore(); err != nil {
		t.Fatal(err)
	}
	after := fr.joined()
	if !strings.Contains(after, "Remove-DnsClientNrptRule") {
		t.Fatalf("NRPT rule not removed in:\n%s", after)
	}
	if !strings.Contains(after, "set dns") || !strings.Contains(after, "dhcp") {
		t.Fatalf("resolvers not returned to DHCP in:\n%s", after)
	}
}

func TestLeakState(t *testing.T) {
	fr := &fakeRunner{effective: "10.7.0.1\n"}
	m := New(fr, "veilnet", WithStateDir(t.TempDir()))
	if err := m.Apply(CUSTOM, []string{"10.7.0.1"}); err != nil {
		t.Fatal(err)
	}
	st := m.LeakState()
	if st.Route != "tunnel" || st.Leaking {
		t.Fatalf("clean tunnel state misreported: %+v", st)
	}
	fr.effective = "10.7.0.1\n192.168.1.1\n"
	st = m.LeakState()
	if !st.Leaking || st.Route != "system" {
		t.Fatalf("leak not detected: %+v", st)
	}
	if len(st.Resolvers) != 2 {
		t.Fatalf("resolvers = %v", st.Resolvers)
	}
}

func TestDOHRejectsUnknown(t *testing.T) {
	m := New(&fakeRunner{}, "veilnet", WithStateDir(t.TempDir()))
	if err := m.Apply(DOH, []string{"203.0.113.53"}); err == nil {
		t.Fatal("unknown DoH server must be rejected, not downgraded")
	}
	fr := &fakeRunner{}
	m2 := New(fr, "veilnet", WithStateDir(t.TempDir()))
	if err := m2.Apply(DOH, []string{"1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fr.joined(), "dohtemplate=https://cloudflare-dns.com/dns-query") {
		t.Fatalf("DoH template not registered:\n%s", fr.joined())
	}
}

func TestSystemIsExplicitRestore(t *testing.T) {
	fr := &fakeRunner{}
	m := New(fr, "veilnet", WithStateDir(t.TempDir()))
	if err := m.Apply(VEILNET, []string{"10.7.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply(SYSTEM, nil); err != nil {
		t.Fatal(err)
	}
	if m.Mode() != SYSTEM || len(m.Servers()) != 0 {
		t.Fatal("SYSTEM must clear tunnel servers")
	}
}
