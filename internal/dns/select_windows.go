package dns

// selectBackend returns the DNS backend for Windows builds.
func selectBackend() Backend { return windowsBackend{} }
