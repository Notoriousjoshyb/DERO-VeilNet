package routing

// selectBackend returns the routing backend for Linux builds.
func selectBackend() Backend { return linuxBackend{} }
