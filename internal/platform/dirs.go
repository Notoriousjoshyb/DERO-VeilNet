package platform

import (
	"os"
	"path/filepath"
	"runtime"
)

// Dirs holds the per-OS application directories for config, data and state.
type Dirs struct {
	// Config holds user-editable configuration.
	Config string
	// Data holds persistent application data (databases, snapshots).
	Data string
	// State holds crash-recovery sentinels and other restart state.
	State string
}

// AppDirs returns the conventional per-OS directories for VeilNet:
//
//	Windows: %AppData%/veilnet (config), %LocalAppData%/veilnet (data + state)
//	Linux:   XDG_CONFIG_HOME / XDG_DATA_HOME / XDG_STATE_HOME with ~/. fallbacks
//	macOS:   ~/Library/Application Support/veilnet, Caches for state
func AppDirs() Dirs {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			appdata = filepath.Join(home, "AppData", "Roaming")
		}
		local := os.Getenv("LOCALAPPDATA")
		if local == "" {
			local = filepath.Join(home, "AppData", "Local")
		}
		return Dirs{
			Config: filepath.Join(appdata, "veilnet"),
			Data:   filepath.Join(local, "veilnet"),
			State:  filepath.Join(local, "veilnet", "state"),
		}
	case "darwin":
		support := filepath.Join(home, "Library", "Application Support", "veilnet")
		return Dirs{
			Config: support,
			Data:   support,
			State:  filepath.Join(home, "Library", "Caches", "veilnet"),
		}
	default: // linux and other unix-likes honour XDG
		cfg := os.Getenv("XDG_CONFIG_HOME")
		if cfg == "" {
			cfg = filepath.Join(home, ".config")
		}
		data := os.Getenv("XDG_DATA_HOME")
		if data == "" {
			data = filepath.Join(home, ".local", "share")
		}
		state := os.Getenv("XDG_STATE_HOME")
		if state == "" {
			state = filepath.Join(home, ".local", "state")
		}
		return Dirs{
			Config: filepath.Join(cfg, "veilnet"),
			Data:   filepath.Join(data, "veilnet"),
			State:  filepath.Join(state, "veilnet"),
		}
	}
}

// Ensure creates the Config, Data and State directories.
func (d Dirs) Ensure() error {
	for _, p := range []string{d.Config, d.Data, d.State} {
		if p == "" {
			continue
		}
		if err := os.MkdirAll(p, 0o700); err != nil {
			return err
		}
	}
	return nil
}
