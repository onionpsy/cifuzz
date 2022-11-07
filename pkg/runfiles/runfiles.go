package runfiles

import (
	"os"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/internal/installer"
)

type RunfilesFinder interface {
	CIFuzzIncludePath() (string, error)
	ClangPath() (string, error)
	CMakePath() (string, error)
	CMakePresetsPath() (string, error)
	LLVMCovPath() (string, error)
	LLVMProfDataPath() (string, error)
	LLVMSymbolizerPath() (string, error)
	Minijail0Path() (string, error)
	ProcessWrapperPath() (string, error)
	ReplayerSourcePath() (string, error)
	VSCodeTasksPath() (string, error)
	LogoPath() (string, error)
	MavenPath() (string, error)
	GradlePath() (string, error)
	GradleClasspathScriptPath() (string, error)
	JavaHomePath() (string, error)
}

var Finder RunfilesFinder

func init() {
	// Set the default runfiles finder.
	//
	// If the environment variable CIFUZZ_INSTALL_ROOT is set, we use
	// that as the installation directory otherwise we check the standard
	// installation directory.
	installDir, found := os.LookupEnv("CIFUZZ_INSTALL_ROOT")
	if !found || installDir == "" {
		var err error
		installDir, err = installer.GetInstallDir()
		if err != nil {
			panic(errors.WithStack(err))
		}
	}

	Finder = RunfilesFinderImpl{InstallDir: installDir}
}
