package cmdutils

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mattn/go-zglob"
	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/util/fileutil"
)

var jazzerFuzzTestRegex = regexp.MustCompile(`@FuzzTest|\sfuzzerTestOneInput\(`)

func JazzerSeedCorpus(targetClass string, projectDir string) string {
	seedCorpus := targetClass + "Inputs"
	path := strings.Split(seedCorpus, ".")
	path = append([]string{"src", "test", "resources"}, path...)

	return filepath.Join(projectDir, filepath.Join(path...))
}

func JazzerGeneratedCorpus(targetClass string, projectDir string) string {
	return filepath.Join(projectDir, ".cifuzz-corpus", targetClass)
}

// ConstructJVMFuzzTestIdentifier constructs a fully qualified class name for a
// given fuzz test file from the directory the file is in and the file name.
func ConstructJVMFuzzTestIdentifier(path, testDir string) (string, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return "", errors.WithStack(err)
	}

	match := jazzerFuzzTestRegex.MatchString(string(bytes))
	if match {
		classFilePath, err := filepath.Rel(testDir, path)
		if err != nil {
			return "", errors.WithStack(err)
		}

		className := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))

		fuzzTestIdentifier := filepath.Join(
			filepath.Dir(classFilePath),
			className,
		)
		fuzzTestIdentifier = strings.ReplaceAll(fuzzTestIdentifier, string(os.PathSeparator), ".")
		// remove language specific paths from identifier for example src/test/(java|kotlin)
		fuzzTestIdentifier = strings.TrimPrefix(fuzzTestIdentifier, "java.")
		fuzzTestIdentifier = strings.TrimPrefix(fuzzTestIdentifier, "kotlin.")

		return fuzzTestIdentifier, nil
	}

	return "", nil
}

// ListJVMFuzzTests returns a list of all fuzz tests in the project.
// The returned list contains the fully qualified class name of the fuzz test.
func ListJVMFuzzTests(projectDir string) ([]string, error) {
	return ListJVMFuzzTestsWithFilter(projectDir, "")
}

// ListJVMFuzzTestsWithFilter returns a list of all fuzz tests in the project.
// The returned list contains the fully qualified class name of the fuzz test.
// to filter files based on the fqcn you can use the prefix filter parameter
func ListJVMFuzzTestsWithFilter(projectDir string, prefixFilter string) ([]string, error) {
	testDir := filepath.Join(projectDir, "src", "test")
	exists, err := fileutil.Exists(testDir)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}

	// use zglob to support globbing in windows
	matches, err := zglob.Glob(filepath.Join(testDir, "**", "*.{java,kt}"))
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var fuzzTests []string
	for _, match := range matches {
		fuzzTestIdentifier, err := ConstructJVMFuzzTestIdentifier(match, testDir)
		if err != nil {
			return nil, err
		}
		if fuzzTestIdentifier != "" && (prefixFilter == "" || strings.HasPrefix(fuzzTestIdentifier, prefixFilter)) {
			fuzzTests = append(fuzzTests, fuzzTestIdentifier)
		}
	}

	return fuzzTests, nil
}
