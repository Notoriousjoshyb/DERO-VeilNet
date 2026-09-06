// Package ipc serves the privileged-service channel.
//
// Windows named pipe: \\.\pipe\veilnet-service, auth token file
// ~/.veilnet/service.token (32 random bytes hex); non-Windows fallback
// 127.0.0.1 TCP + same token.
//
// Scaffold placeholder: the owning agent implements this package.
package ipc
