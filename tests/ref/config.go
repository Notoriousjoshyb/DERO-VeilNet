package ref

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

// Contract config paths. home is the user home; production callers pass
// os.UserHomeDir(). The functions take home explicitly so tests run isolated.
func ClientConfigPath(home string) string { return filepath.Join(home, ".veilnet", "config.toml") }
func NodeConfigPath(home string) string   { return filepath.Join(home, ".veilnet-node", "config.toml") }
func ServiceTokenPath(home string) string { return filepath.Join(home, ".veilnet", "service.token") }

// EnsureServiceToken creates the IPC auth token file (32 random bytes hex,
// 64 chars) with owner-only permissions when absent, and returns its content.
// Existing files are read back unchanged so service restarts keep the token.
func EnsureServiceToken(home string) (string, error) {
	p := ServiceTokenPath(home)
	if data, err := os.ReadFile(p); err == nil {
		tok := string(data)
		if len(tok) != 64 {
			return "", errors.New("ref: service token corrupt (want 64 hex chars)")
		}
		if _, err := hex.DecodeString(tok); err != nil {
			return "", errors.New("ref: service token not hex")
		}
		return tok, nil
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw[:])
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(p, []byte(tok), 0o600); err != nil {
		return "", err
	}
	return tok, nil
}

// TokenFilePerm returns the permission bits of path for least-privilege
// assertions (0600 on POSIX; Windows ACLs approximate — caller skips there).
func TokenFilePerm(path string) (os.FileMode, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return fi.Mode().Perm(), nil
}
