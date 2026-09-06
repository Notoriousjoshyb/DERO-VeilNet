package dns

// selectBackend returns the DNS backend for macOS builds.
func selectBackend() Backend { return darwinBackend{} }
