package platform

// ServiceSpec describes the OS service/daemon that hosts the privileged
// VeilNet data plane.
type ServiceSpec struct {
	// Name is the OS service identifier (SCM name, unit name, launchd label).
	Name string
	// Display is the human-readable service name.
	Display string
	// Exec is the service binary (basename on Windows, path on unix).
	Exec string
}

// DefaultService returns the per-OS privileged service specification.
func DefaultService() ServiceSpec {
	switch CurrentOS() {
	case Windows:
		return ServiceSpec{Name: "veilnet", Display: "VeilNet Service", Exec: "veilnet-service.exe"}
	case Darwin:
		return ServiceSpec{Name: "net.veilnet.daemon", Display: "VeilNet", Exec: "/usr/local/bin/veilnet-service"}
	default:
		return ServiceSpec{Name: "veilnet", Display: "VeilNet Service", Exec: "/usr/local/bin/veilnet-service"}
	}
}

// InstallHint returns the one-command privileged-service install for this OS.
// Onboarding surfaces this verbatim in "service not installed" errors.
func (s ServiceSpec) InstallHint() string {
	switch CurrentOS() {
	case Windows:
		return `sc create veilnet binPath= "veilnet-service.exe" start= auto && sc start veilnet`
	case Darwin:
		return "sudo cp packaging/launchd/net.veilnet.daemon.plist /Library/LaunchDaemons/ && sudo launchctl load /Library/LaunchDaemons/net.veilnet.daemon.plist"
	default:
		return "sudo cp packaging/systemd/veilnet.service /etc/systemd/system/ && sudo systemctl enable --now veilnet"
	}
}
