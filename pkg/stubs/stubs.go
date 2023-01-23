package stubs

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/util/fileutil"
)

//go:embed fuzz-test.cpp.tmpl
var cppStub []byte

//go:embed fuzzTest.java.tmpl
var javaStub []byte

//go:embed fuzzTest.ktl.tmpl
var kotlinStub []byte

// Create creates a stub based for the given test type
func Create(path string, testType config.FuzzTestType) error {
	exists, err := fileutil.Exists(path)
	if err != nil {
		return err
	}
	if exists {
		return errors.WithStack(os.ErrExist)
	}

	// read matching template
	var content []byte
	switch testType {
	case config.CPP:
		content = cppStub
	case config.JAVA, config.KOTLIN:
		var ext, langInPath, stub string
		if testType == config.JAVA {
			ext = ".java"
			langInPath = "java"
			stub = string(javaStub)
		} else if testType == config.KOTLIN {
			ext = ".kt"
			langInPath = "kotlin"
			stub = string(kotlinStub)
		}

		baseName := strings.TrimSuffix(filepath.Base(path), ext)
		content = []byte(strings.Replace(stub, "__CLASS_NAME__", baseName, 1))

		// If we have a valid package name we add it to the template
		// We assume the project has the standard java project structure
		if filepath.Dir(path) != "" {
			packagePath := strings.TrimPrefix(filepath.Dir(path), filepath.Join("src", "test", langInPath)+string(os.PathSeparator))
			packagePath = strings.ReplaceAll(packagePath, string(os.PathSeparator), ".")

			packageName := fmt.Sprintf("package %s;", packagePath)
			if testType == config.KOTLIN {
				strings.TrimSuffix(packageName, ";")
			}
			content = []byte(strings.Replace(string(content), "__PACKAGE__", packageName, 1))
		}
	}

	// write stub
	if content != nil && path != "" {
		if err := os.WriteFile(path, content, 0644); err != nil {
			return errors.WithStack(err)
		}
	}
	return nil
}

// FuzzTestFilename returns a proposal for a filename,
// depending on the test type and given directory.
// The filename should follow the conventions of the type.
func FuzzTestFilename(testType config.FuzzTestType) (string, error) {
	var filePattern, basename, ext, filename string

	switch testType {
	case config.CPP:
		basename = "my_fuzz_test"
		ext = "cpp"
		filePattern = "%s_%d.%s"
	case config.KOTLIN:
		basename = "MyClassFuzzTest"
		ext = "kt"
		filePattern = "%s%d.%s"
	case config.JAVA:
		basename = "MyClassFuzzTest"
		ext = "java"
		filePattern = "%s%d.%s"
	default:
		return "", errors.New("unable to suggest filename: unknown test type")
	}

	for counter := 1; ; counter++ {
		filename = filepath.Join(".", fmt.Sprintf(filePattern, basename, counter, ext))
		exists, err := fileutil.Exists(filename)
		if err != nil {
			return "", err
		}

		if !exists {
			return filename, nil
		}
	}
}
