package firewall

// selectBackend returns the kill-switch backend for Linux builds.
func selectBackend() Backend { return linuxBackend{} }
