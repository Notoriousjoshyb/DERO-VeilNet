// Package ios is the thin gomobile bind target for the VeilNet mobile
// library (experimental).
//
// Bind with:
//
//	gomobile bind -target=ios -o Veilnet.xcframework \
//	  github.com/dero-veilnet/veilnet/mobile/veilnet
//
// iOS hosts import the framework and call the string-envelope API
// (Configure/SelectNode/Start/Stop/Status/Diagnostics); see README.md
// for the Swift call pattern. No logic lives here.
package ios
