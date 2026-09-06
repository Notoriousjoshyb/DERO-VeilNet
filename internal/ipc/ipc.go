// Package ipc implements the privileged-service channel.
//
// Windows: named pipe \\.\pipe\veilnet-service.
// Non-Windows: 127.0.0.1 TCP (DefaultTCPAddr).
// Every request carries the auth token from ~/.veilnet/service.token
// (32 random bytes hex, 0600). The GUI never needs admin: the service
// hosts the tunnel engine, firewall, and DNS while the GUI dials it.
package ipc

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// PipeName is the Windows named-pipe address.
const PipeName = `\\.\pipe\veilnet-service`

// DefaultTCPAddr is the non-Windows fallback listen address.
const DefaultTCPAddr = "127.0.0.1:18441"

// Shared operation names between service and GUI dialer.
const (
	OpStatus         = "status"
	OpConnect        = "connect"
	OpDisconnect     = "disconnect"
	OpListNodes      = "list-nodes"
	OpDiagnostics    = "diagnostics"
	OpGetConfig      = "get-config"
	OpSetConfig      = "set-config"
	OpPayment        = "payment"
	OpCircuit        = "circuit"
	OpRotate         = "rotate"
	OpApprovePayment = "approve-payment"
	OpConfirmPayment = "confirm-payment"
	OpWalletStatus     = "wallet-status"
	OpWalletConnect    = "wallet-connect"
	OpWalletDisconnect = "wallet-disconnect"
	OpWalletPay        = "wallet-pay"
)

// Request is one framed call. Token uses constant-time comparison server-side.
type Request struct {
	Token   string          `json:"token"`
	Op      string          `json:"op"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Response answers a Request.
type Response struct {
	OK      bool            `json:"ok"`
	Error   string          `json:"error,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Handler serves one op. Payload is decoded by the service.
type Handler func(op string, payload json.RawMessage) (any, error)

// TokenPath returns ~/.veilnet/service.token.
func TokenPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".veilnet", "service.token"), nil
}

// LoadOrCreateToken reads the token file or creates it (0600, 0700 dir).
func LoadOrCreateToken(path string) (string, error) {
	if path == "" {
		p, err := TokenPath()
		if err != nil {
			return "", err
		}
		path = p
	}
	if data, err := os.ReadFile(path); err == nil {
		tok := string(data)
		if len(tok) == 64 {
			return tok, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(raw[:])
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(tok), 0o600); err != nil {
		return "", err
	}
	return tok, nil
}

// LoadToken reads an existing token file.
func LoadToken(path string) (string, error) {
	if path == "" {
		p, err := TokenPath()
		if err != nil {
			return "", err
		}
		path = p
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) != 64 {
		return "", fmt.Errorf("bad token file %s", path)
	}
	return string(data), nil
}

func writeFrame(conn net.Conn, v any) error {
	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	return json.NewEncoder(conn).Encode(v)
}

func readFrame(conn net.Conn, v any) error {
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	return json.NewDecoder(conn).Decode(v)
}
