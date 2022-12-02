package dependencies

import (
	"github.com/Masterminds/semver"

	"code-intelligence.com/cifuzz/pkg/log"
)

type Dependencies map[Key]*Dependency

// List of all known dependencies
var deps = Dependencies{
	CLANG: {
		Key:        CLANG,
		MinVersion: *semver.MustParse("11.0.0"),
		GetVersion: func(dep *Dependency) (*semver.Version, error) {
			return clangVersion(dep, clangCheck)
		},
		Installed: func(dep *Dependency) bool {
			return dep.checkFinder(dep.finder.ClangPath)
		},
	},
	CMAKE: {
		Key:        CMAKE,
		MinVersion: *semver.MustParse("3.16.0"),
		GetVersion: cmakeVersion,
		Installed: func(dep *Dependency) bool {
			return dep.checkFinder(dep.finder.CMakePath)
		},
	},
	LLVM_COV: {
		Key:        LLVM_COV,
		MinVersion: *semver.MustParse("11.0.0"),
		GetVersion: func(dep *Dependency) (*semver.Version, error) {
			path, err := dep.finder.LLVMCovPath()
			if err != nil {
				return nil, err
			}
			version, err := llvmVersion(path, dep)
			if err != nil {
				return nil, err
			}
			log.Debugf("Found llvm-cov version %s in PATH: %s", version, path)
			return version, nil
		},
		Installed: func(dep *Dependency) bool {
			return dep.checkFinder(dep.finder.LLVMCovPath)
		},
	},
	LLVM_PROFDATA: {
		Key: LLVM_PROFDATA,
		// llvm-profdata provides no version information
		MinVersion: *semver.MustParse("0.0.0"),
		GetVersion: func(dep *Dependency) (*semver.Version, error) {
			return semver.NewVersion("0.0.0")
		},
		Installed: func(dep *Dependency) bool {
			path, err := dep.finder.LLVMProfDataPath()
			if err != nil {
				return false
			}
			log.Debugf("Found llvm-profdata in PATH: %s", path)
			return true
		},
	},
	LLVM_SYMBOLIZER: {
		Key:        LLVM_SYMBOLIZER,
		MinVersion: *semver.MustParse("11.0.0"),
		GetVersion: func(dep *Dependency) (*semver.Version, error) {
			path, err := dep.finder.LLVMSymbolizerPath()
			if err != nil {
				return nil, err
			}
			version, err := llvmVersion(path, dep)
			if err != nil {
				return nil, err
			}
			log.Debugf("Found llvm-symbolizer version %s in PATH: %s", version, path)
			return version, nil
		},
		Installed: func(dep *Dependency) bool {
			return dep.checkFinder(dep.finder.LLVMSymbolizerPath)
		},
	},
	GENHTML: {
		Key:        GENHTML,
		MinVersion: *semver.MustParse("0.0.0"),
		GetVersion: func(dep *Dependency) (*semver.Version, error) {
			return semver.NewVersion("0.0.0")
		},
		Installed: func(dep *Dependency) bool {
			path, err := dep.finder.GenHTMLPath()
			if err != nil {
				return false
			}
			log.Debugf("Found genhtml in PATH: %s", path)
			return true
		},
	},
	JAVA: {
		Key:        JAVA,
		MinVersion: *semver.MustParse("8.0.0"),
		GetVersion: javaVersion,
		Installed: func(dep *Dependency) bool {
			return dep.checkFinder(dep.finder.JavaHomePath)
		},
	},
	MAVEN: {
		Key:        MAVEN,
		MinVersion: *semver.MustParse("0.0.0"),
		GetVersion: func(dep *Dependency) (*semver.Version, error) {
			return semver.NewVersion("0.0.0")
		},
		Installed: func(dep *Dependency) bool {
			return dep.checkFinder(dep.finder.MavenPath)
		},
	},
	GRADLE: {
		Key:        GRADLE,
		MinVersion: *semver.MustParse("0.0.0"),
		GetVersion: func(dep *Dependency) (*semver.Version, error) {
			return semver.NewVersion("0.0.0")
		},
		Installed: func(dep *Dependency) bool {
			return dep.checkFinder(dep.finder.GradlePath)
		},
	},
}

// CIFuzzBazelCommit is the commit of the
// https://github.com/CodeIntelligenceTesting/cifuzz-bazel
// repository that is required by this version of cifuzz.
//
// Keep in sync with examples/bazel/WORKSPACE.
const CIFuzzBazelCommit = "b013aa0f90fe8ac60adfc6d9640a9cfa451dda9e"
