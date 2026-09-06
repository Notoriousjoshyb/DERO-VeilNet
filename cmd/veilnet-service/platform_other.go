//go:build !windows

package main

import (
	"fmt"
	"net"
)

func isWindows() bool { return false }

func listenPipe() (net.Listener, error) {
	return nil, fmt.Errorf("named pipes are Windows-only")
}
