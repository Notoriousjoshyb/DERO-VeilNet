package dns

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var errNoResolved = errors.New("fake: no resolvectl")

// scriptedRunner answers canned output per command substring so backend
// branches (resolved vs fallback, networksetup vs scutil) are testable.
type scriptedRunner struct {
	mu      sync.Mutex
	calls   []string
	outputs map[string]string
	errs    map[string]error
}

func newScripted(outputs map[string]string, errs map[string]error) *scriptedRunner {
	return &scriptedRunner{outputs: outputs, errs: errs}
}

func (r *scriptedRunner) Run(name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, cmd)
	for sub, err := range r.errs {
		if strings.Contains(cmd, sub) {
			return r.outputs[sub], err
		}
	}
	for sub, out := range r.outputs {
		if strings.Contains(cmd, sub) {
			return out, nil
		}
	}
	return "", nil
}
func (r *scriptedRunner) joined() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.calls, "\n")
}
// Windows path: interface DNS + NRPT catch-all applied together, both
// removed on restore with DHCP reinstated (zero residual).
func TestWindowsBackendSymmetric(t *testing.T) {
	be := windowsBackend{}
	fr := &fakeRunner{effective: "10.7.0.1\n"}
	if got := be.Current(fr, "veilnet"); len(got) != 1 || got[0] != "192.168.1.1" {
		t.Fatalf("snapshot source = %v", got)
	}
	if err := be.Set(fr, "veilnet", []string{"10.7.0.1"}); err != nil {
		t.Fatal(err)
	}
	if log := fr.joined(); !strings.Contains(log, "set dns") ||
		!strings.Contains(log, "Add-DnsClientNrptRule") ||
		!strings.Contains(log, `-Namespace "."`) {
		t.Fatalf("apply incomplete in:\n%s", log)
	}
	if err := be.RegisterDOH(fr, []string{"1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fr.joined(), "dohtemplate=https://cloudflare-dns.com/dns-query") {
		t.Fatalf("DoH template not registered in:\n%s", fr.joined())
	}
	if err := be.RegisterDOH(fr, []string{"203.0.113.53"}); err == nil {
		t.Fatal("unknown DoH server must be rejected, not downgraded")
	}
	if err := be.Restore(fr, "veilnet", []string{"192.168.1.1"}); err != nil {
		t.Fatal(err)
	}
	after := fr.joined()
	if !strings.Contains(after, "Remove-DnsClientNrptRule") {
		t.Fatalf("NRPT rule not removed in:\n%s", after)
	}
	if !strings.Contains(after, "set dns") || !strings.Contains(after, "dhcp") {
		t.Fatalf("resolvers not returned to DHCP in:\n%s", after)
	}
	if !strings.Contains(after, "192.168.1.1") {
		t.Fatalf("prior static resolver not reinstated in:\n%s", after)
	}
}

// Linux resolved path: resolvectl carries DNS + search domain; revert
// restores previous state.
func TestLinuxBackendResolvedSymmetric(t *testing.T) {
	be := linuxBackend{}
	r := newScripted(map[string]string{
		"resolvectl --version": "systemd 254\n",
		"resolvectl dns":       "Link 3 (veilnet): 10.7.0.1\n",
	}, nil)
	if err := be.Set(r, "veilnet", []string{"10.7.0.1"}); err != nil {
		t.Fatal(err)
	}
	if log := r.joined(); !strings.Contains(log, "resolvectl dns veilnet 10.7.0.1") ||
		!strings.Contains(log, "resolvectl domain veilnet ~.") {
		t.Fatalf("resolved apply incomplete in:\n%s", log)
	}
	if got := be.Effective(r, "veilnet"); len(got) != 1 || got[0] != "10.7.0.1" {
		t.Fatalf("effective = %v", got)
	}
	if err := be.Restore(r, "veilnet", []string{"192.168.1.1"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.joined(), "resolvectl revert veilnet") {
		t.Fatalf("revert missing in:\n%s", r.joined())
	}
	if err := be.RegisterDOH(r, []string{"1.1.1.1"}); err == nil {
		t.Fatal("DoH must fail explicitly on linux, not silently downgrade")
	}
}

// Linux fallback path: without resolved, /etc/resolv.conf is rewritten
// and the prior content restored exactly (zero residual tunnel entries).
func TestLinuxBackendResolvConfFallback(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "resolv.conf")
	be := linuxBackend{ResolvConfPath: conf}
	r := newScripted(nil, map[string]error{"resolvectl": errNoResolved})
	if err := be.Set(r, "veilnet", []string{"10.7.0.1", "10.7.0.2"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "nameserver 10.7.0.1") ||
		!strings.Contains(string(raw), "nameserver 10.7.0.2") {
		t.Fatalf("fallback file wrong:\n%s", raw)
	}
	if got := be.Current(r, "veilnet"); len(got) != 2 {
		t.Fatalf("snapshot source = %v", got)
	}
	if err := be.Restore(r, "veilnet", []string{"192.168.1.1"}); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "10.7.0.") {
		t.Fatalf("tunnel resolver lingers in:\n%s", raw)
	}
	if !strings.Contains(string(raw), "nameserver 192.168.1.1") {
		t.Fatalf("prior resolver not restored in:\n%s", raw)
	}
}

// macOS path: networksetup applies and reinstates; Empty restores DHCP
// when no prior resolvers existed.
func TestDarwinBackendSymmetric(t *testing.T) {
	be := darwinBackend{}
	r := newScripted(map[string]string{
		"-getdnsservers": "10.7.0.1\n",
	}, nil)
	if err := be.Set(r, "veilnet", []string{"10.7.0.1"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.joined(), "-setdnsservers veilnet 10.7.0.1") {
		t.Fatalf("apply missing in:\n%s", r.joined())
	}
	if got := be.Effective(r, "veilnet"); len(got) != 1 || got[0] != "10.7.0.1" {
		t.Fatalf("effective = %v", got)
	}
	if err := be.Restore(r, "veilnet", []string{"192.168.1.1"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.joined(), "-setdnsservers veilnet 192.168.1.1") {
		t.Fatalf("prior not reinstated in:\n%s", r.joined())
	}
	r2 := newScripted(nil, nil)
	if err := be.Restore(r2, "veilnet", nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r2.joined(), "-setdnsservers veilnet Empty") {
		t.Fatalf("DHCP not restored in:\n%s", r2.joined())
	}
	if err := be.RegisterDOH(r, []string{"1.1.1.1"}); err == nil {
		t.Fatal("DoH must fail explicitly on darwin, not silently downgrade")
	}
}

// Manager delegates to the injected backend end to end.
func TestManagerDelegatesToBackend(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "resolv.conf")
	be := linuxBackend{ResolvConfPath: conf}
	r := newScripted(nil, map[string]error{"resolvectl": errNoResolved})
	m := New(r, "veilnet", WithStateDir(t.TempDir()), WithBackend(be))
	if m.BackendName() != be.Name() {
		t.Fatalf("backend = %s", m.BackendName())
	}
	if err := m.Apply(VEILNET, []string{"10.7.0.1"}); err != nil {
		t.Fatal(err)
	}
	if st := m.LeakState(); st.Route != "tunnel" || st.Leaking {
		t.Fatalf("clean tunnel state misreported: %+v", st)
	}
	if err := m.Restore(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(conf)
	if strings.Contains(string(raw), "10.7.0.1") {
		t.Fatalf("tunnel resolver lingers in:\n%s", raw)
	}
	_ = dir
}
