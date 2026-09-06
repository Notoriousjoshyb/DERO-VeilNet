// Package veilnet is the pure-Go VeilNet client SDK (beta).
//
// The core Client depends only on the small interfaces in this package
// (Discovery, Connector, Observer), whose shapes mirror internal/app and
// internal/registry without importing them, so there are no import
// cycles. adapter_app.go binds those interfaces to the real *app.App;
// consumers with their own backends implement the interfaces directly.
package veilnet
