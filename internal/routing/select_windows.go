package routing

// selectBackend returns the routing backend for Windows builds.
func selectBackend() Backend { return windowsBackend{} }
