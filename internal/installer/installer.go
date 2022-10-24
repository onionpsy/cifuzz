package installer

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/pkg/errors"
)

var Deps = []string{
	"cmd", "internal", "pkg", "util", "third-party/minijail",
}

// GetInstallDir returns the absolute path to the installation
// directory which is chosen according to the OS, root privileges
// and environment variables.
func GetInstallDir() (string, error) {
	var installDir string

	xdgPath, xdgSet := os.LookupEnv("XDG_DATA_HOME")

	switch {
	case runtime.GOOS == "windows":
		appdata, err := os.UserConfigDir()
		if err != nil {
			return "", errors.WithStack(err)
		}
		installDir = filepath.Join(appdata, "cifuzz")
	case os.Getuid() == 0:
		installDir = "/opt/code-intelligence/cifuzz"
	case xdgSet:
		installDir = filepath.Join(xdgPath, "cifuzz")
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return "", errors.WithStack(err)
		}
		installDir = filepath.Join(home, ".local", "share", "cifuzz")
	}

	installDir, err := filepath.Abs(installDir)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return installDir, nil
}

func GetBinDir() (string, error) {
	var binDir string
	var err error

	// Executable should be in installation directory on Windows
	if runtime.GOOS == "windows" {
		installDir, err := GetInstallDir()
		if err != nil {
			return "", err
		}
		binDir = filepath.Join(installDir, "bin")
	} else if os.Getuid() == 0 {
		binDir = "/usr/local/bin"
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", errors.WithStack(err)
		}
		binDir = filepath.Join(home, ".local", "bin")
	}

	binDir, err = filepath.Abs(binDir)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return binDir, nil
}
