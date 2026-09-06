package routing

// selectBackend returns the routing backend for macOS builds.
func selectBackend() Backend { return darwinBackend{} }
