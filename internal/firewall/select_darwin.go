package firewall

// selectBackend returns the kill-switch backend for macOS builds.
func selectBackend() Backend { return darwinBackend{} }
