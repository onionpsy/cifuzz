package cmdutils

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pkg/errors"
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

func ConstructJavaFuzzTestIdentifier(path, testDir string) (string, error) {
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
		className := strings.TrimSuffix(filepath.Base(path), ".java")

		fuzzTestIdentifier := filepath.Join(
			filepath.Dir(classFilePath),
			className,
		)
		fuzzTestIdentifier = strings.ReplaceAll(fuzzTestIdentifier, string(os.PathSeparator), ".")

		return fuzzTestIdentifier, nil
	}

	return "", errors.New("Could not create class name for target file.")
}
