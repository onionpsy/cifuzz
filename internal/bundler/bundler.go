package bundler

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/artifact"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/vcs"
	"code-intelligence.com/cifuzz/util/fileutil"
	"code-intelligence.com/cifuzz/util/sliceutil"
)

// The (possibly empty) directory inside the fuzzing artifact archive that will
// be the fuzzers working directory.
const workDirPath = "work_dir"

type Bundler struct {
	opts *Opts
}

func New(opts *Opts) *Bundler {
	return &Bundler{opts: opts}
}

func (b *Bundler) Bundle() error {
	// create temp dir
	var err error
	b.opts.tempDir, err = os.MkdirTemp("", "cifuzz-bundle-")
	if err != nil {
		return errors.WithStack(err)
	}
	defer fileutil.Cleanup(b.opts.tempDir)

	var manifest archiveManifest
	var fuzzers []*artifact.Fuzzer

	switch b.opts.BuildSystem {
	case config.BuildSystemCMake, config.BuildSystemBazel, config.BuildSystemOther:
		fuzzers, manifest, err = newLibfuzzerBundler(b.opts).bundle()
	case config.BuildSystemMaven, config.BuildSystemGradle:
		fuzzers, manifest, err = newJazzerBundler(b.opts).bundle()
	}
	if err != nil {
		return err
	}

	err = b.createWorkDir(manifest)
	if err != nil {
		return err
	}

	err = b.createMetadataFile(fuzzers, manifest)
	if err != nil {
		return err
	}

	err = b.store(manifest)
	if err != nil {
		return err
	}

	return nil
}

func (b *Bundler) createWorkDir(archiveManifest archiveManifest) error {
	// The fuzzing artifact archive spec requires this directory even if it is empty.
	tmpWorkDirPath := filepath.Join(b.opts.tempDir, workDirPath)
	err := os.MkdirAll(tmpWorkDirPath, 0o755)
	if err != nil {
		return errors.WithStack(err)
	}
	archiveManifest[workDirPath] = tmpWorkDirPath
	return nil
}

// Create and add the top-level metadata file.
func (b *Bundler) createMetadataFile(fuzzers []*artifact.Fuzzer, archiveManifest archiveManifest) error {
	metadata := &artifact.Metadata{
		Fuzzers: fuzzers,
		RunEnvironment: &artifact.RunEnvironment{
			Docker: b.opts.DockerImage,
		},
		CodeRevision: b.getCodeRevision(),
	}
	metadataYamlContent, err := metadata.ToYaml()
	if err != nil {
		return err
	}
	metadataYamlPath := filepath.Join(b.opts.tempDir, artifact.MetadataFileName)
	err = os.WriteFile(metadataYamlPath, metadataYamlContent, 0o644)
	if err != nil {
		return errors.Wrapf(err, "failed to write %s", artifact.MetadataFileName)
	}
	archiveManifest[artifact.MetadataFileName] = metadataYamlPath

	return nil
}

// Store to archive
func (b *Bundler) store(archiveManifest archiveManifest) error {
	if b.opts.OutputPath == "" {
		if len(b.opts.FuzzTests) == 1 {
			b.opts.OutputPath = filepath.Base(b.opts.FuzzTests[0]) + ".tar.gz"
		} else {
			b.opts.OutputPath = "fuzz_tests.tar.gz"
		}
	}

	archive, err := os.Create(b.opts.OutputPath)
	if err != nil {
		return errors.Wrap(err, "failed to create fuzzing artifact archive")
	}
	archiveWriter := bufio.NewWriter(archive)
	defer archiveWriter.Flush()
	err = artifact.WriteArchive(archiveWriter, archiveManifest)
	if err != nil {
		return errors.Wrap(err, "failed to write fuzzing artifact archive")
	}
	log.Successf("Successfully created artifact: %s", b.opts.OutputPath)

	return nil
}

func (b *Bundler) getCodeRevision() *artifact.CodeRevision {
	var err error
	var gitCommit string
	var gitBranch string

	if b.opts.Commit == "" {
		gitCommit, err = vcs.GitCommit()
		if err != nil {
			log.Debugf("failed to get Git commit: %+v", err)
			return nil
		}
	} else {
		gitCommit = b.opts.Commit
	}

	if b.opts.Branch == "" {
		gitBranch, err = vcs.GitBranch()
		if err != nil {
			log.Debugf("failed to get Git branch: %+v", err)
			return nil
		}
	} else {
		gitBranch = b.opts.Branch
	}

	if vcs.GitIsDirty() {
		log.Warnf("The Git repository has uncommitted changes. Archive metadata may be inaccurate.")
	}

	return &artifact.CodeRevision{
		Git: &artifact.GitRevision{
			Commit: gitCommit,
			Branch: gitBranch,
		},
	}
}

func prepareSeeds(seedCorpusDirs []string, archiveSeedsDir string, manifest archiveManifest) error {
	var targetDirs []string
	for _, sourceDir := range seedCorpusDirs {
		// Put the seeds into subdirectories of the "seeds" directory
		// to avoid seeds with the same name to override each other.

		// Choose a name for the target directory which wasn't used
		// before
		basename := filepath.Join(archiveSeedsDir, filepath.Base(sourceDir))
		targetDir := basename
		i := 1
		for sliceutil.Contains(targetDirs, targetDir) {
			targetDir = fmt.Sprintf("%s-%d", basename, i)
			i++
		}
		targetDirs = append(targetDirs, targetDir)

		// Add the seeds of the seed corpus directory to the target directory
		err := artifact.AddDirToManifest(manifest, targetDir, sourceDir)
		if err != nil {
			return err
		}
	}
	return nil
}
