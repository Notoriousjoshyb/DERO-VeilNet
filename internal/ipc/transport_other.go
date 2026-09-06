//go:build !windows

package ipc

import "net"

// ListenTCP listens on a TCP address (default non-Windows transport).
func ListenTCP(addr string) (net.Listener, error) {
	if addr == "" {
		addr = DefaultTCPAddr
	}
	return net.Listen("tcp", addr)
}

// defaultDial dials the TCP fallback.
func defaultDial() (net.Conn, error) {
	return net.Dial("tcp", DefaultTCPAddr)
}
