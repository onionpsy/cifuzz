package e2e

import (
	"bytes"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"testing"

	"code-intelligence.com/cifuzz/integration-tests/shared"
	"code-intelligence.com/cifuzz/pkg/cicheck"
	"code-intelligence.com/cifuzz/util/fileutil"
)

type Assertion func(*testing.T, CommandOutput)

type CommandOutput struct {
	ExitCode int
	Stdout   string
	Stderr   string
	Stdall   string // Combined stdout and stderr output for simpler assertions
	Workdir  fs.FS  // Expose files from the test folder
}

type TestCase struct {
	Description  string
	Command      string
	Environment  []string
	Args         []string
	SampleFolder []string
	// Os        []OSRuntime // When we will have tests depending on the OS
	// Ciuser    CIUser # TODO: should set a CI token when relevant
	// ToolsRequired []string # TODO: depending on the tools we will want to test
	Assert Assertion
}

type testCaseRunOptions struct {
	command      string
	args         string
	sampleFolder string
}

// RunTests Runs all test cases generated from the input combinations
func RunTests(t *testing.T, testCases []TestCase) {
	for _, testCase := range testCases {
		runTest(t, &testCase)
	}
}

// runTest Generates 1...n tests from possible combinations in a TestCase.
func runTest(t *testing.T, testCase *TestCase) {
	if testing.Short() {
		t.Skip("skipping e2e tests in short mode")
	}

	if cicheck.IsCIEnvironment() && os.Getenv("E2E_TESTS_MATRIX") == "" {
		t.Skip("Skipping e2e tests. You need to set E2E_TESTS_MATRIX envvar to run this test.")
	}

	fmt.Println("Running test: ", testCase.Description)

	// Set defaults
	if len(testCase.Args) == 0 {
		testCase.Args = []string{""}
	}

	if len(testCase.SampleFolder) == 0 {
		testCase.SampleFolder = []string{"empty"}
	}

	// Generate all the combinations we want to test
	testCaseRuns := []testCaseRunOptions{}
	for _, args := range testCase.Args {
		for _, contextFolder := range testCase.SampleFolder {
			testCaseRuns = append(testCaseRuns, testCaseRunOptions{
				command:      testCase.Command,
				args:         args,
				sampleFolder: contextFolder,
			})
		}
	}

	for index, testCaseRun := range testCaseRuns {
		t.Run(fmt.Sprintf("[%d/%d] cifuzz %s %s", index+1, len(testCaseRuns), testCaseRun.command, testCaseRun.args), func(t *testing.T) {
			contextFolder := shared.CopyTestdataDirForE2E(t, testCaseRun.sampleFolder)
			defer fileutil.Cleanup(contextFolder)

			// exec.Cmd can't handle empty args
			var cmd *exec.Cmd
			if len(testCaseRun.args) > 0 {
				cmd = exec.Command("cifuzz", testCaseRun.command, testCaseRun.args)
			} else {
				cmd = exec.Command("cifuzz", testCaseRun.command)
			}

			// add env vars
			cmd.Env = append(cmd.Env, testCase.Environment...)

			cmd.Dir = contextFolder

			stdout := bytes.Buffer{}
			errout := bytes.Buffer{}
			cmd.Stdout = &stdout
			cmd.Stderr = &errout

			err := cmd.Run()
			if err != nil {
				log.Printf("Error running command: %v", err)
			}

			testCase.Assert(t, CommandOutput{
				ExitCode: cmd.ProcessState.ExitCode(),
				Stdout:   stdout.String(),
				Stderr:   errout.String(),
				Stdall:   stdout.String() + errout.String(),
				Workdir:  os.DirFS(contextFolder),
			})
		})
	}
}
