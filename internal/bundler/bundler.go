package bundler

import (
	"bufio"
	"os"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/artifact"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/fileutil"
)

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

	var archiveManifest archiveManifest

	switch b.opts.BuildSystem {
	case config.BuildSystemCMake, config.BuildSystemBazel, config.BuildSystemOther:
		archiveManifest, err = newLibfuzzerBundler(b.opts).bundle()
	case config.BuildSystemMaven, config.BuildSystemGradle:
		archiveManifest, err = newJazzerBundler(b.opts).bundle()
	}
	if err != nil {
		return err
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
