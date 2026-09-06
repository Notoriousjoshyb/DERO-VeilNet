//go:build windows

package ipc

import (
	"net"

	"github.com/Microsoft/go-winio"
)

// ListenPipe listens on the Windows named pipe.
func ListenPipe() (net.Listener, error) {
	return winio.ListenPipe(PipeName, nil)
}

// defaultDial dials the Windows named pipe.
func defaultDial() (net.Conn, error) {
	return winio.DialPipe(PipeName, nil)
}

// ListenTCP listens on a TCP address (tests and tooling).
func ListenTCP(addr string) (net.Listener, error) {
	if addr == "" {
		addr = DefaultTCPAddr
	}
	return net.Listen("tcp", addr)
}
