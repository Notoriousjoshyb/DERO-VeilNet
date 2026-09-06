// Package veilnet is the gomobile-compatible mobile library (experimental).
//
// gomobile binding rules shape this API: every exported function takes
// and returns only strings (JSON envelopes), and the package exports no
// structs with func/chan fields and no interface parameters. The
// backend interface is deliberately unexported — Go hosts inject one
// via SetBackend (also unexported... see backend_go.go); gomobile
// consumers use Configure/Start/Stop/Status/SelectNode/Diagnostics,
// which drive the same internal/app control plane as desktop (no forked
// tunnel or payments logic).
package veilnet
