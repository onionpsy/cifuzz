package ldd

import (
	"path/filepath"

	"code-intelligence.com/cifuzz/util/sliceutil"
)

func LibraryPaths(executable string) ([]string, error) {
	var libraryPaths []string
	libs, err := NonSystemSharedLibraries(executable)
	if err != nil {
		return nil, err
	}
	for _, lib := range libs {
		libraryPath := filepath.Dir(lib)
		if !sliceutil.Contains(libraryPaths, libraryPath) {
			libraryPaths = append(libraryPaths, libraryPath)
		}
	}
	return libraryPaths, nil
}
