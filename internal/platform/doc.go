// Package platform centralises every operating-system decision in VeilNet.
//
// All OS branches live here (or in per-OS *_windows.go / *_linux.go /
// *_darwin.go backend files). Shared logic elsewhere must consume this
// package instead of switching on runtime.GOOS.
package platform
