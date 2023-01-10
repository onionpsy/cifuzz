package resolve

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/internal/config"
)

func TestResolveBazel(t *testing.T) {
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		err = os.Chdir(oldWd)
		require.NoError(t, err)
	}()

	err = os.Chdir(filepath.Join("testdata", "bazel"))
	require.NoError(t, err)
	pwd, err := os.Getwd()
	require.NoError(t, err)

	fuzzTestName := "//src/fuzz_test_1:fuzz_test_1"

	// relative path
	srcFile := filepath.Join("src", "fuzz_test_1", "fuzz_test.cpp")
	resolved, err := resolve(srcFile, config.BuildSystemBazel, pwd)
	require.NoError(t, err)
	require.Equal(t, fuzzTestName, resolved)

	// absolute path
	srcFile = filepath.Join(pwd, srcFile)
	resolved, err = resolve(srcFile, config.BuildSystemBazel, pwd)
	require.NoError(t, err)
	require.Equal(t, fuzzTestName, resolved)

}

func TestResolveCMake(t *testing.T) {
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		err = os.Chdir(oldWd)
		require.NoError(t, err)
	}()

	err = os.Chdir(filepath.Join("testdata", "cmake"))
	require.NoError(t, err)

	pwd, err := os.Getwd()
	require.NoError(t, err)

	fuzzTestName := "fuzz_test_1"

	// relative path
	srcFile := filepath.Join("src", "fuzz_test_1", "fuzz_test.cpp")
	resolved, err := resolve(srcFile, config.BuildSystemCMake, pwd)
	assert.NoError(t, err)
	assert.Equal(t, fuzzTestName, resolved)

	// absolute path
	srcFile = filepath.Join(pwd, srcFile)
	resolved, err = resolve(srcFile, config.BuildSystemCMake, pwd)
	require.NoError(t, err)
	require.Equal(t, fuzzTestName, resolved)
}

func TestResolveMavenGradle(t *testing.T) {
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		err = os.Chdir(oldWd)
		require.NoError(t, err)
	}()

	err = os.Chdir(filepath.Join("testdata", "maven_gradle"))
	require.NoError(t, err)

	pwd, err := os.Getwd()
	require.NoError(t, err)

	fuzzTestName := "com.example.fuzz_test_1.FuzzTestCase"
	// relative path
	srcFile := filepath.Join("src", "test", "java", "com", "example", "fuzz_test_1", "FuzzTestCase.java")
	resolved, err := resolve(srcFile, config.BuildSystemGradle, pwd)
	assert.NoError(t, err)
	assert.Equal(t, fuzzTestName, resolved)
	resolved, err = resolve(srcFile, config.BuildSystemMaven, pwd)
	assert.NoError(t, err)
	assert.Equal(t, fuzzTestName, resolved)

	// absolute path
	srcFile = filepath.Join(pwd, srcFile)
	resolved, err = resolve(srcFile, config.BuildSystemGradle, pwd)
	assert.NoError(t, err)
	assert.Equal(t, fuzzTestName, resolved)
	resolved, err = resolve(srcFile, config.BuildSystemMaven, pwd)
	assert.NoError(t, err)
	assert.Equal(t, fuzzTestName, resolved)
}
