// Package config resolves runtime paths and defaults.
// On Linux we follow the standard FHS layout. On Windows (dev) everything
// goes under %LOCALAPPDATA%\TunnelDeck so the binary runs without root.
package config

import (
	"os"
	"path/filepath"
	"runtime"
)

type Config struct {
	StateDir  string
	ConfigDir string
	BackupDir string
	LogDir    string
	DBPath    string

	DefaultUIBind    string
	DefaultUIPort    int
	DefaultWGIface   string
	DefaultWGPort    int
	DefaultWGSubnet  string
	DefaultGatewayWG string
	ManagedNFTTable  string
}

func Defaults() Config {
	c := Config{
		DefaultUIBind:    "127.0.0.1",
		DefaultUIPort:    9443,
		DefaultWGIface:   "wg0",
		DefaultWGPort:    51820,
		DefaultWGSubnet:  "10.66.66.0/24",
		DefaultGatewayWG: "10.66.66.1/24",
		ManagedNFTTable:  "tunneldeck_nat",
	}

	if runtime.GOOS == "linux" {
		c.StateDir = "/var/lib/tunneldeck"
		c.ConfigDir = "/etc/tunneldeck"
		c.LogDir = "/var/log/tunneldeck"
	} else {
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			base, _ = os.UserConfigDir()
		}
		if base == "" {
			base = "."
		}
		c.StateDir = filepath.Join(base, "TunnelDeck", "state")
		c.ConfigDir = filepath.Join(base, "TunnelDeck", "config")
		c.LogDir = filepath.Join(base, "TunnelDeck", "logs")
	}
	c.BackupDir = filepath.Join(c.StateDir, "backups")
	c.DBPath = filepath.Join(c.StateDir, "tunneldeck.db")
	return c
}

func (c Config) EnsureDirs() error {
	for _, d := range []string{c.StateDir, c.ConfigDir, c.BackupDir, c.LogDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return err
		}
	}
	return nil
}
