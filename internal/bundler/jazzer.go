package bundler

type jazzerBundler struct {
	opts *Opts
}

func newJazzerBundler(opts *Opts) *jazzerBundler {
	return &jazzerBundler{opts}
}

func (b *jazzerBundler) bundle() (archiveManifest, error) {
	// check dependencies

	// build

	// copy to temp dir and deduplication

	// create archive manifest
	archiveManifest := archiveManifest{}

	// store to archive

	return archiveManifest, nil
}
