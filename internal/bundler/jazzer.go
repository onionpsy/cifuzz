package bundler

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/viper"

	"code-intelligence.com/cifuzz/internal/build"
	"code-intelligence.com/cifuzz/internal/build/gradle"
	"code-intelligence.com/cifuzz/internal/build/maven"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/artifact"
	"code-intelligence.com/cifuzz/pkg/dependencies"
	"code-intelligence.com/cifuzz/pkg/runfiles"
)

type jazzerBundler struct {
	opts *Opts
}

func newJazzerBundler(opts *Opts) *jazzerBundler {
	return &jazzerBundler{opts}
}

func (b *jazzerBundler) bundle() ([]*artifact.Fuzzer, archiveManifest, error) {
	depsOk, err := b.checkDependencies()
	if err != nil {
		return nil, nil, err
	}
	if !depsOk {
		return nil, nil, dependencies.Error()
	}

	buildResults, err := b.runBuild()
	if err != nil {
		return nil, nil, err
	}

	return b.assembleArtifacts(buildResults)
}

func (b *jazzerBundler) assembleArtifacts(buildResults []*build.Result) ([]*artifact.Fuzzer, archiveManifest, error) {
	var fuzzers []*artifact.Fuzzer

	// create archive manifest
	manifest := archiveManifest{}

	archiveSeedDir, err := b.copySeeds(manifest)
	if err != nil {
		return nil, nil, err
	}

	// Iterate over build results to fill manifest and create fuzzers
	for _, buildResult := range buildResults {
		runtimePaths := []string{}
		for _, runtimeDep := range buildResult.RuntimeDeps {
			// check if the file exists
			entry, err := os.Stat(runtimeDep)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return nil, nil, errors.WithStack(err)
			}

			if entry.IsDir() {
				// if the current runtime dep is a directory, add all files to
				// the archive but add just the directory path to the runtime
				// paths. Hence, there will be a single entry for the runtime
				// path but multiple entries for the archive manifest.
				relPath, err := filepath.Rel(buildResult.BuildDir, runtimeDep)
				if err != nil {
					return nil, nil, errors.WithStack(err)
				}
				runtimePaths = append(runtimePaths, relPath)

				err = filepath.WalkDir(runtimeDep, func(path string, d os.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if d.IsDir() {
						return nil
					}
					relPath, err := filepath.Rel(buildResult.BuildDir, path)
					if err != nil {
						return err
					}
					manifest[relPath] = path
					return nil
				})
				if err != nil {
					return nil, nil, errors.WithStack(err)
				}
			} else {
				// if the current runtime dependency is a file we add it to the
				// manifest and add the runtime paths of the metadata
				archivePath := filepath.Base(runtimeDep)
				manifest[archivePath] = runtimeDep
				runtimePaths = append(runtimePaths, archivePath)
			}
		}
		fuzzer := &artifact.Fuzzer{
			Target:       buildResult.Name,
			Engine:       "JAVA_LIBFUZZER",
			ProjectDir:   buildResult.ProjectDir,
			Dictionary:   b.opts.Dictionary,
			Seeds:        archiveSeedDir,
			RuntimePaths: runtimePaths,
			EngineOptions: artifact.EngineOptions{
				Env:   b.opts.Env,
				Flags: b.opts.EngineArgs,
			},
			MaxRunTime: uint(b.opts.Timeout.Seconds()),
		}
		fuzzers = append(fuzzers, fuzzer)
	}
	return fuzzers, manifest, nil
}

func (b *jazzerBundler) copySeeds(manifest archiveManifest) (string, error) {
	archiveSeedDir := "seeds"
	err := prepareSeeds(b.opts.SeedCorpusDirs, archiveSeedDir, manifest)
	if err != nil {
		return "", err
	}
	return archiveSeedDir, nil
}

func (b *jazzerBundler) checkDependencies() (bool, error) {
	var deps []dependencies.Key
	switch b.opts.BuildSystem {
	case config.BuildSystemMaven:
		deps = []dependencies.Key{dependencies.JAVA, dependencies.MAVEN}
		return dependencies.Check(deps, dependencies.MavenDeps, runfiles.Finder)
	case config.BuildSystemGradle:
		deps = []dependencies.Key{dependencies.JAVA, dependencies.GRADLE}
		return dependencies.Check(deps, dependencies.GradleDeps, runfiles.Finder)
	}
	return false, errors.New("invalid build system")
}

func (b *jazzerBundler) runBuild() ([]*build.Result, error) {
	var buildResults []*build.Result
	switch b.opts.BuildSystem {
	case config.BuildSystemMaven:
		builder, err := maven.NewBuilder(&maven.BuilderOptions{
			ProjectDir: b.opts.ProjectDir,
			Parallel: maven.ParallelOptions{
				Enabled: viper.IsSet("build-jobs"),
				NumJobs: b.opts.NumBuildJobs,
			},
			Stdout: b.opts.Stdout,
			Stderr: b.opts.Stderr,
		})
		if err != nil {
			return nil, err
		}
		for _, test := range b.opts.FuzzTests {
			buildResult, err := builder.Build(test)
			if err != nil {
				return nil, err
			}
			buildResults = append(buildResults, buildResult)
		}
	case config.BuildSystemGradle:
		builder, err := gradle.NewBuilder(&gradle.BuilderOptions{
			ProjectDir: b.opts.ProjectDir,
			Parallel: gradle.ParallelOptions{
				Enabled: viper.IsSet("build-jobs"),
				NumJobs: b.opts.NumBuildJobs,
			},
			Stdout: b.opts.Stdout,
			Stderr: b.opts.Stderr,
		})
		if err != nil {
			return nil, err
		}
		for _, test := range b.opts.FuzzTests {
			buildResult, err := builder.Build(test)
			if err != nil {
				return nil, err
			}
			buildResults = append(buildResults, buildResult)
		}
	}

	return buildResults, nil
}
