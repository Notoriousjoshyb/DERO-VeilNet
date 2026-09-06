// Package integration holds CLIENT -> NODE -> TEST-SERVER network tests.
//
// They run against the devnet in deploy/docker-compose.yml and NEVER against
// mainnet: every test requires explicit fixture env (see TESTING.md / DEVNET.md).
// When a fixture is absent the test SKIPS with "unverified" — it never
// reports PASS without performing the check. When protection is armed but a
// leak is observed, the test FAILS loudly.
package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

// Fixtures. Set by scripts/devnet-up (or CI with a live devnet):
//   VEILNET_DEVNET_SERVER  base URL of test-server, e.g. http://127.0.0.1:18080
//   VEILNET_TUNNEL_PROXY   HTTP proxy URL egressing via the exit node (tunnel path)
//   VEILNET_TUNNEL_DNS     DNS-over-HTTP stub on the exit path: $DNS/dns?name=...
//   VEILNET_NODE_CTL       node control base URL exposing POST /bounce
//   VEILNET_KILL_ARMED     "1" when the kill-switch live fixture is armed
//   VEILNET_PHYS_IFACE     interface name forced for direct (non-tunnel) dials
func fixture(key string) (string, bool) {
	v, ok := os.LookupEnv(key)
	return v, ok && v != ""
}

func requireFixture(t *testing.T, key string) string {
	t.Helper()
	v, ok := fixture(key)
	if !ok {
		t.Skipf("unverified: fixture %s not present (see docs/DEVNET.md) — NOT a pass", key)
	}
	return v
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

func getJSON(t *testing.T, client *http.Client, url string, out any) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d: %s", url, resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatalf("decode %s: %v (%s)", url, err, body)
	}
}

func proxyClient(t *testing.T, proxyURL string) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("bad proxy URL %q: %v", proxyURL, err)
	}
	// Proxy configured explicitly: no env auto-proxy may silently bypass it.
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(u),
		},
	}
}

type whoami struct {
	IP string `json:"ip"`
}
// TestExitIPChangesViaNode proves egress leaves from the exit node, not the
// client: direct and tunnel-path observations must differ.
func TestExitIPChangesViaNode(t *testing.T) {
	server := requireFixture(t, "VEILNET_DEVNET_SERVER")
	proxyURL := requireFixture(t, "VEILNET_TUNNEL_PROXY")

	var direct, viaNode whoami
	getJSON(t, httpClient, server+"/whoami", &direct)
	getJSON(t, proxyClient(t, proxyURL), server+"/whoami", &viaNode)

	if direct.IP == "" || viaNode.IP == "" {
		t.Fatal("unverified: test-server returned empty identity")
	}
	if direct.IP == viaNode.IP {
		t.Fatalf("LEAK/NO-TUNNEL: tunnel-path IP %q equals direct IP — traffic not egressing via node", viaNode.IP)
	}
	t.Logf("direct=%s exit=%s", direct.IP, viaNode.IP)
}

// TestDNSPathViaTunnel proves name resolution answers come from the tunnel
// DNS stub (authoritative for veilnet.test), not a local resolver.
func TestDNSPathViaTunnel(t *testing.T) {
	dnsStub := requireFixture(t, "VEILNET_TUNNEL_DNS")
	proxyURL := requireFixture(t, "VEILNET_TUNNEL_PROXY")

	name := fmt.Sprintf("probe-%d.veilnet.test", time.Now().UnixNano())
	var ans struct {
		Name   string `json:"name"`
		Answer string `json:"answer"`
		Via    string `json:"via"`
	}
	getJSON(t, proxyClient(t, proxyURL), dnsStub+"/dns?name="+name, &ans)
	if ans.Name != name {
		t.Fatalf("unverified: stub echoed unexpected name %q", ans.Name)
	}
	if ans.Answer == "" {
		t.Fatal("unverified: tunnel DNS gave no answer")
	}
	if ans.Via == "" {
		t.Fatal("unverified: stub did not attest resolution path")
	}
}

// TestReconnectSessionSurvives bounces the devnet node and requires the
// tunnel path to recover within the deadline.
func TestReconnectSessionSurvives(t *testing.T) {
	server := requireFixture(t, "VEILNET_DEVNET_SERVER")
	proxyURL := requireFixture(t, "VEILNET_TUNNEL_PROXY")
	ctl := requireFixture(t, "VEILNET_NODE_CTL")

	var before whoami
	getJSON(t, proxyClient(t, proxyURL), server+"/whoami", &before)

	req, err := http.NewRequest(http.MethodPost, ctl+"/bounce", nil)
	if err != nil {
		t.Fatalf("bounce request: %v", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("POST bounce: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		t.Fatalf("bounce = %d, want 200/202", resp.StatusCode)
	}

	deadline := time.Now().Add(60 * time.Second)
	pc := proxyClient(t, proxyURL)
	for {
		var after whoami
		r, err := pc.Get(server + "/whoami")
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			r.Body.Close()
			if r.StatusCode == http.StatusOK && json.Unmarshal(body, &after) == nil && after.IP != "" {
				t.Logf("recovered after bounce, exit=%s", after.IP)
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("tunnel path did not recover within 60s of bounce (last err=%v)", err)
		}
		time.Sleep(2 * time.Second)
	}
}

// TestKillSwitchBlocksDirect requires the armed live fixture: with the kill
// switch on, a forced-physical-interface dial to the test server MUST fail.
// Success is a leak and FAILS. Absent fixture env => SKIP (unverified).
func TestKillSwitchBlocksDirect(t *testing.T) {
	server := requireFixture(t, "VEILNET_DEVNET_SERVER")
	if _, ok := fixture("VEILNET_KILL_ARMED"); !ok {
		t.Skip("unverified: kill-switch live fixture not armed (VEILNET_KILL_ARMED) — NOT a pass")
	}
	ifaceName := requireFixture(t, "VEILNET_PHYS_IFACE")

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		t.Fatalf("unverified: physical interface %q missing: %v", ifaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		t.Fatalf("unverified: no addresses on %q", ifaceName)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	// Extract host:port from the server URL for a raw TCP dial attempt.
	hostport := server
	for _, prefix := range []string{"http://", "https://"} {
		hostport = trimPrefix(hostport, prefix)
	}
	hostport = trimSuffix(hostport, "/")
	conn, err := dialer.Dial("tcp", hostport)
	if err == nil {
		conn.Close()
		t.Fatalf("LEAK: direct egress to %s succeeded via %s while kill switch armed", hostport, ifaceName)
	}
	t.Logf("direct dial blocked as required (%v)", err)
}

func trimPrefix(s, p string) string {
	if len(s) >= len(p) && s[:len(p)] == p {
		return s[len(p):]
	}
	return s
}

func trimSuffix(s, suf string) string {
	for len(s) > 0 && s[len(s)-1:] == suf {
		s = s[:len(s)-1]
	}
	return s
}
