// Package tunnel defines the TunnelEngine interface and shared tunnel types.
//
// The binding contract lives here (see Contract):
//
//	type Engine interface {
//		Start(cfg WireGuardConfig) error
//		Stop() error
//		Status() Status
//		Statistics() Stats
//		ApplyConfiguration(cfg WireGuardConfig) error
//		RotateEndpoint(endpoint string) error
//	}
//
// Scaffold placeholder: the owning agent implements this package.
package tunnel
