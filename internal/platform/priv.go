package platform

// NeedsPrivilegedService reports whether VeilNet's data-plane work
// (tunnel device, firewall, routes, DNS) requires a privileged helper or
// service. That is true on every supported OS: raw TUN + firewall + route
// mutation always needs elevation.
func NeedsPrivilegedService() bool { return true }
