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
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/artifact"
	"code-intelligence.com/cifuzz/pkg/dependencies"
	"code-intelligence.com/cifuzz/pkg/log"
)

// The directory inside the fuzzing artifact used to store runtime dependencies
const runtimeDepsPath = "runtime_deps"

type jazzerBundler struct {
	opts *Opts
}

func newJazzerBundler(opts *Opts) *jazzerBundler {
	return &jazzerBundler{opts}
}

func (b *jazzerBundler) bundle() ([]*artifact.Fuzzer, artifact.FileMap, error) {
	err := b.checkDependencies()
	if err != nil {
		return nil, nil, err
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

	var archiveDict string
	if b.opts.Dictionary != "" {
		archiveDict = "dict"
		archiveFileMap[archiveDict] = b.opts.Dictionary
	}

	// Iterate over build results to fill archive file map and create fuzzers
	for _, buildResult := range buildResults {
		log.Printf("build dir: %s\n", buildResult.BuildDir)
		// copy seeds for every fuzz test
		archiveSeedsDir, err := b.copySeeds(buildResult, archiveFileMap)
		if err != nil {
			return nil, nil, err
		}

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
			log.Printf("runtime dept: %s\n", runtimeDep)
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
				relPath, err := filepath.Rel(buildResult.ProjectDir, runtimeDep)
				if err != nil {
					return nil, nil, errors.WithStack(err)
				}
				relPath = filepath.Join(runtimeDepsPath, relPath)
				runtimePaths = append(runtimePaths, relPath)

				err = artifact.AddDirToFileMap(archiveFileMap, relPath, runtimeDep)
				if err != nil {
					return nil, nil, errors.WithStack(err)
				}
			} else {
				// if the current runtime dependency is a file we add it to the
				// file map and add the runtime paths of the metadata
				archivePath := filepath.Join(runtimeDepsPath, filepath.Base(runtimeDep))
				archiveFileMap[archivePath] = runtimeDep
				runtimePaths = append(runtimePaths, archivePath)
			}
		}

		fuzzer := &artifact.Fuzzer{
			Name:         buildResult.Name,
			Engine:       "JAVA_LIBFUZZER",
			ProjectDir:   buildResult.ProjectDir,
			Dictionary:   archiveDict,
			Seeds:        archiveSeedsDir,
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

func (b *jazzerBundler) copySeeds(buildResult *build.Result, archiveFileMap artifact.FileMap) (string, error) {
	// Add seeds from user-specified seed corpus dirs (if any)
	// to the seeds directory in the archive
	var archiveSeedsDir string
	if len(b.opts.SeedCorpusDirs) > 0 {
		archiveSeedsDir = "seeds"
		err := prepareSeeds(b.opts.SeedCorpusDirs, archiveSeedsDir, archiveFileMap)
		if err != nil {
			return "", err
		}
	}

	return archiveSeedsDir, nil
}

func (b *jazzerBundler) checkDependencies() error {
	var deps []dependencies.Key
	switch b.opts.BuildSystem {
	case config.BuildSystemMaven:
		deps = []dependencies.Key{dependencies.JAVA, dependencies.MAVEN}
	case config.BuildSystemGradle:
		deps = []dependencies.Key{dependencies.JAVA, dependencies.GRADLE}
	}
	err := dependencies.Check(deps)
	if err != nil {
		log.Error(err)
		return cmdutils.WrapSilentError(err)
	}
	return nil
}

func (b *jazzerBundler) runBuild() ([]*build.Result, error) {
	var fuzzTests []string
	var err error

	if len(b.opts.FuzzTests) == 0 {
		fuzzTests, err = build.ListJazzerFuzzTests(b.opts.ProjectDir)
		if err != nil {
			return nil, err
		}
	} else {
		fuzzTests = b.opts.FuzzTests
	}

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

		for _, test := range fuzzTests {
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
		for _, test := range fuzzTests {
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
	defer jarFile.Close()
	jarWriter := zip.NewWriter(jarFile)
	defer jarWriter.Close()

	// create explicit parent directory in zip file
	fh := &zip.FileHeader{
		Name: "META-INF/",
	}
	fh.SetMode(0o755)
	_, err = jarWriter.CreateHeader(fh)
	if err != nil {
		return "", errors.WithStack(err)
	}

	// add manifest file
	fh = &zip.FileHeader{
		Name: filepath.Join("META-INF", "MANIFEST.MF"),
	}
	fh.SetMode(0o644)
	manifestFile, err := jarWriter.CreateHeader(fh)
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
