// Package android is the thin gomobile bind target for the VeilNet
// mobile library (experimental).
//
// This package exists so `gomobile bind` has a stable import path:
//
//	gomobile bind -o veilnet.aar \
//	  github.com/dero-veilnet/veilnet/mobile/veilnet
//
// Android hosts consume the AAR and call the string-envelope API
// (Configure/SelectNode/Start/Stop/Status/Diagnostics); see README.md
// for the Kotlin call pattern. No logic lives here.
package android
