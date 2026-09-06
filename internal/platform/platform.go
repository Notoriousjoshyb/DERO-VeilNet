package platform

import "runtime"

// OS is a supported operating system family.
type OS string

// Supported OS families.
const (
	Windows OS = "windows"
	Linux   OS = "linux"
	Darwin  OS = "darwin"
	Other   OS = "other"
)

// CurrentOS reports the OS family this binary is running on.
func CurrentOS() OS {
	switch runtime.GOOS {
	case "windows":
		return Windows
	case "linux":
		return Linux
	case "darwin":
		return Darwin
	default:
		return Other
	}
}

// String returns the runtime.GOOS-style name.
func (o OS) String() string { return string(o) }
