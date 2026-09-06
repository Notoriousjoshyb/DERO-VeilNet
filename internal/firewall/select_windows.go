package firewall

// selectBackend returns the kill-switch backend for Windows builds.
func selectBackend() Backend { return windowsBackend{} }
