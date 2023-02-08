//go:build !windows

package other

import (
	"regexp"
	"strings"

	"github.com/u-root/u-root/pkg/ldd"
)

func findSharedLibraries(executable string) ([]string, error) {
	var sharedObjects []string

	// ldd provides the complete list of dynamic dependencies of a dynamically linked file.
	// That is, we don't have to recursively query the transitive dynamic dependencies.
	filesInfo, err := ldd.Ldd([]string{executable})
	if err != nil {
		return nil, err
	}

	for _, fileInfo := range filesInfo {
		if !isStandardSystemLibrary(fileInfo.FullName) {
			sharedObjects = append(sharedObjects, fileInfo.FullName)
		}
	}

	return sharedObjects, err
}

var sharedLibraryRegex = regexp.MustCompile(`^.+\.((so)|(dylib))(\.\d\w*)*$`)

func isStandardSystemLibrary(library string) bool {
	if !sharedLibraryRegex.MatchString(library) {
		return false
	}

	for _, stdLibTopDir := range []string{"/usr", "/lib", "/lib64", "/lib32", "libx32"} {
		if strings.HasPrefix(library, stdLibTopDir) {
			return false
		}
	}

	return true
}
