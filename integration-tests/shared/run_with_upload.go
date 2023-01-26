package shared

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/util/envutil"
	"code-intelligence.com/cifuzz/util/executil"
	"code-intelligence.com/cifuzz/util/fileutil"
)

func TestRunWithUpload(t *testing.T, dir string, cifuzz string, args ...string) {
	projectName := "test-project"
	token := "test-token"

	// Start a mock server to handle our requests
	server := StartMockServer(t, projectName, "")

	tempDir, err := os.MkdirTemp("", "cifuzz-run-*")
	require.NoError(t, err)
	defer fileutil.Cleanup(tempDir)

	// Create a dictionary
	dictPath := filepath.Join(tempDir, "some_dict")
	err = os.WriteFile(dictPath, []byte("test-dictionary-content"), 0o600)
	require.NoError(t, err)

	// Create a seed corpus directory with an empty seed
	seedCorpusDir, err := os.MkdirTemp(tempDir, "seeds-")
	require.NoError(t, err)
	err = fileutil.Touch(filepath.Join(seedCorpusDir, "empty"))
	require.NoError(t, err)

	args = append(
		[]string{
			"run",
			"--dict", dictPath,
			"--seed-corpus", seedCorpusDir,
			"--project", projectName,
			"--server", server.Address,
			"--interactive=false",
		}, args...)

	cmd := executil.Command(cifuzz, args...)
	cmd.Env, err = envutil.Setenv(os.Environ(), "CIFUZZ_API_TOKEN", token)
	require.NoError(t, err)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
}
