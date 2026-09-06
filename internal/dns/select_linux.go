package dns

// selectBackend returns the DNS backend for Linux builds.
func selectBackend() Backend { return linuxBackend{} }
