//go:build windows

package main

import (
	"net"

	"github.com/dero-veilnet/veilnet/internal/ipc"
)

func isWindows() bool { return true }

func listenPipe() (net.Listener, error) {
	return ipc.ListenPipe()
}
