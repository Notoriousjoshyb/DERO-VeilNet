package veilnettest

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/dero-veilnet/veilnet/tests/ref"
)

func TestConfigPathsMatchContract(t *testing.T) {
	home := string(filepath.Separator) + filepath.Join("home", "user")
	if got := ref.ClientConfigPath(home); !strings.HasSuffix(got, filepath.Join(".veilnet", "config.toml")) {
		t.Fatalf("client path = %q", got)
	}
	if got := ref.NodeConfigPath(home); !strings.HasSuffix(got, filepath.Join(".veilnet-node", "config.toml")) {
		t.Fatalf("node path = %q", got)
	}
	if ref.ClientConfigPath(home) == ref.NodeConfigPath(home) {
		t.Fatal("client and node config must never share a file")
	}
	if got := ref.ServiceTokenPath(home); !strings.HasSuffix(got, filepath.Join(".veilnet", "service.token")) {
		t.Fatalf("service token path = %q", got)
	}
}

func TestServiceTokenCreatedOnceAndStable(t *testing.T) {
	home := t.TempDir()
	first, err := ref.EnsureServiceToken(home)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if len(first) != 64 {
		t.Fatalf("token len = %d, want 64 hex chars (32 bytes)", len(first))
	}
	if _, err := hex.DecodeString(first); err != nil {
		t.Fatalf("token not hex: %v", err)
	}
	second, err := ref.EnsureServiceToken(home)
	if err != nil {
		t.Fatalf("re-Ensure: %v", err)
	}
	if first != second {
		t.Fatal("service restart must keep the same token")
	}
}

func TestServiceTokenFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACLs approximate owner-only; enforced by service ACL setup, not mode bits")
	}
	home := t.TempDir()
	tok, err := ref.EnsureServiceToken(home)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	perm, err := ref.TokenFilePerm(ref.ServiceTokenPath(home))
	if err != nil {
		t.Fatalf("Perm: %v", err)
	}
	if perm != 0o600 {
		t.Fatalf("token file perm = %o, want 600", perm)
	}
	if _, err := os.ReadFile(ref.ServiceTokenPath(home)); err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = tok
}

func TestServiceTokenCorruptRefused(t *testing.T) {
	home := t.TempDir()
	p := ref.ServiceTokenPath(home)
	if _, err := ref.EnsureServiceToken(home); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if err := os.WriteFile(p, []byte("truncated"), 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	if _, err := ref.EnsureServiceToken(home); err == nil {
		t.Fatal("corrupt token file must be refused, not silently reused")
	}
}
