package bundler

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
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
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/runfiles"
)

type jazzerBundler struct {
	opts *Opts
}

func newJazzerBundler(opts *Opts) *jazzerBundler {
	return &jazzerBundler{opts}
}

func (b *jazzerBundler) bundle() ([]*artifact.Fuzzer, artifact.FileMap, error) {
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

func (b *jazzerBundler) assembleArtifacts(buildResults []*build.Result) ([]*artifact.Fuzzer, artifact.FileMap, error) {
	var fuzzers []*artifact.Fuzzer

	// create the filemap for the archive
	archiveFileMap := artifact.FileMap{}

	archiveSeedDir, err := b.copySeeds(archiveFileMap)
	if err != nil {
		return nil, nil, err
	}

	// Iterate over build results to fill archive file map and create fuzzers
	for _, buildResult := range buildResults {

		// creating a manifest.jar for every fuzz test to configure
		// jazzer via MANIFEST.MF
		manifestJar, err := b.createManifestJar(buildResult.Name)
		if err != nil {
			return nil, nil, err
		}
		archiveManifestPath := filepath.Join(buildResult.Name, "manifest.jar")
		archiveFileMap[archiveManifestPath] = manifestJar
		// making sure the manifest jar is the first entry in the class path
		runtimePaths := []string{
			archiveManifestPath,
		}

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
				// path but multiple entries for the archive file map.
				relPath, err := filepath.Rel(buildResult.BuildDir, runtimeDep)
				if err != nil {
					return nil, nil, errors.WithStack(err)
				}
				runtimePaths = append(runtimePaths, relPath)

				err = artifact.AddDirToFileMap(archiveFileMap, relPath, runtimeDep)
				if err != nil {
					return nil, nil, errors.WithStack(err)
				}
			} else {
				// if the current runtime dependency is a file we add it to the
				// file map and add the runtime paths of the metadata
				archivePath := filepath.Base(runtimeDep)
				archiveFileMap[archivePath] = runtimeDep
				runtimePaths = append(runtimePaths, archivePath)
			}
		}

		fuzzer := &artifact.Fuzzer{
			Name:         buildResult.Name,
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
	return fuzzers, archiveFileMap, nil
}

func (b *jazzerBundler) copySeeds(archiveFileMap artifact.FileMap) (string, error) {
	archiveSeedDir := "seeds"
	err := prepareSeeds(b.opts.SeedCorpusDirs, archiveSeedDir, archiveFileMap)
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

// create a manifest.jar to configure jazzer
func (b *jazzerBundler) createManifestJar(targetClass string) (string, error) {
	// create directory for fuzzer specific files
	fuzzerPath := filepath.Join(b.opts.tempDir, targetClass)
	err := os.MkdirAll(fuzzerPath, 0o755)
	if err != nil {
		return "", errors.WithStack(err)
	}

	// create jar archive
	jarPath := filepath.Join(fuzzerPath, "manifest.jar")
	jarFile, err := os.Create(jarPath)
	if err != nil {
		return "", errors.WithStack(err)
	}
	jarWriter := zip.NewWriter(jarFile)

	// create explicit parent directory in zip file
	_, err = jarWriter.Create("META-INF")
	if err != nil {
		return "", errors.WithStack(err)
	}

	// add manifest file
	manifestFile, err := jarWriter.Create(filepath.Join("META-INF", "MANIFEST.MF"))
	if err != nil {
		return "", errors.WithStack(err)
	}

	// create & write content to manifest file
	manifest := fmt.Sprintf("Jazzer-Fuzz-Target-Class: %s", targetClass)

	_, err = io.Copy(manifestFile, bytes.NewBufferString(manifest))
	if err != nil {
		return "", errors.WithStack(err)
	}

	err = jarWriter.Close()
	if err != nil {
		return "", errors.WithStack(err)
	}

	log.Debugf("Created manifest.jar at %s", jarPath)
	return jarPath, nil
}
