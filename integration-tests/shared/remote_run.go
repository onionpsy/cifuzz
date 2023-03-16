package shared

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/integration-tests/shared/mockserver"
	"code-intelligence.com/cifuzz/util/executil"
	"code-intelligence.com/cifuzz/util/fileutil"
)

func TestRemoteRun(t *testing.T, dir string, cifuzz string, args ...string) {
	projectName := "test-project"
	artifactsName := "test-artifacts-123"

	server := mockserver.New(t)

	// define handlers
	server.Handlers["/v1/projects"] = mockserver.ReturnResponse(t, mockserver.ProjectsJSON)
	server.Handlers[fmt.Sprintf("/v2/projects/%s/artifacts/import", projectName)] = mockserver.ReturnResponse(t,
		fmt.Sprintf(`{"display-name": "test-artifacts", "resource-name": %q}`, artifactsName),
	)
	server.Handlers[fmt.Sprintf("/v1/%s:run", artifactsName)] = mockserver.ReturnResponse(t, `{"name": "test-campaign-run-123"}`)

	// start the server
	server.Start(t)

	tempDir, err := os.MkdirTemp("", "cifuzz-archive-*")
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

	// Try to start a remote run on our mock server
	args = append(
		[]string{
			"remote-run",
			"--dict", dictPath,
			"--engine-arg", "arg1",
			"--engine-arg", "arg2",
			"--seed-corpus", seedCorpusDir,
			"--timeout", "100m",
			"--project", projectName,
			"--server", server.Address,
		}, args...)
	cmd := executil.Command(cifuzz, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Terminate the cifuzz process when we receive a termination signal
	// (else the test won't stop).
	TerminateOnSignal(t, cmd)

	t.Logf("Command: %s", cmd.String())
	os.Setenv("CIFUZZ_API_TOKEN", "test-token")
	err = cmd.Run()
	os.Unsetenv("CIFUZZ_API_TOKEN")
	require.NoError(t, err)
}

func TestRemoteRunWithAdditionalArgs(t *testing.T, dir string, cifuzz string, expectedErrorExp *regexp.Regexp, args ...string) {
	var err error
	projectName := "test-project"
	artifactsName := "test-artifacts-123"

	server := mockserver.New(t)

	// define handlers
	server.Handlers["/v1/projects"] = mockserver.ReturnResponse(t, mockserver.ProjectsJSON)
	server.Handlers[fmt.Sprintf("/v2/projects/%s/artifacts/import", projectName)] = mockserver.ReturnResponse(t,
		fmt.Sprintf(`{"display-name": "test-artifacts", "resource-name": %q}`, artifactsName),
	)
	server.Handlers[fmt.Sprintf("/v1/%s:run", artifactsName)] = mockserver.ReturnResponse(t, `{"name": "test-campaign-run-123"}`)

	// start the server
	server.Start(t)

	args = append(
		[]string{
			"remote-run",
			"--project", projectName,
			"--server", server.Address,
		}, args...)
	args = append(args, "--", "--non-existent-flag")
	cmd := executil.Command(cifuzz, args...)
	cmd.Dir = dir

	// Terminate the cifuzz process when we receive a termination signal
	// (else the test won't stop).
	TerminateOnSignal(t, cmd)

	t.Logf("Command: %s", cmd.String())
	os.Setenv("CIFUZZ_API_TOKEN", "test-token")
	output, err := cmd.CombinedOutput()
	os.Unsetenv("CIFUZZ_API_TOKEN")
	require.Error(t, err)

	seenExpectedOutput := expectedErrorExp.MatchString(string(output))
	require.True(t, seenExpectedOutput)
}
