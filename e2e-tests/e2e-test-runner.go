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
	"code-intelligence.com/cifuzz/pkg/detect_ci"
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

type Test struct {
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

type testRunOptions struct {
	command      string
	args         string
	sampleFolder string
}

func RunTest(t *testing.T, testOptions *Test) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}

	if detect_ci.IsCI() && os.Getenv("E2E_TESTS_MATRIX") == "" {
		t.Skip("Skipping test. You need to set E2E_TESTS_MATRIX envvar to run this test locally.")
	}

	// Set defaults
	if len(testOptions.Args) == 0 {
		testOptions.Args = []string{""}
	}

	if len(testOptions.SampleFolder) == 0 {
		testOptions.SampleFolder = []string{"empty"}
	}

	// Generate all the combinations we want to test
	subtests := []testRunOptions{}
	for _, args := range testOptions.Args {
		for _, contextFolder := range testOptions.SampleFolder {
			subtests = append(subtests, testRunOptions{
				command:      testOptions.Command,
				args:         args,
				sampleFolder: contextFolder,
			})
		}
	}

	for index, subtest := range subtests {
		t.Run(fmt.Sprintf("[%d/%d] cifuzz %s %s", index+1, len(subtests), string(subtest.command), subtest.args), func(t *testing.T) {
			contextFolder := shared.CopyTestdataDirForE2E(t, subtest.sampleFolder)
			defer fileutil.Cleanup(contextFolder)

			// exec.Cmd can't handle empty args
			var cmd *exec.Cmd
			if len(subtest.args) > 0 {
				cmd = exec.Command("cifuzz", subtest.command, subtest.args)
			} else {
				cmd = exec.Command("cifuzz", subtest.command)
			}

			// add env vars
			cmd.Env = append(cmd.Env, testOptions.Environment...)

			cmd.Dir = contextFolder

			stdout := bytes.Buffer{}
			errout := bytes.Buffer{}
			cmd.Stdout = &stdout
			cmd.Stderr = &errout

			err := cmd.Run()
			if err != nil {
				log.Printf("Error running command: %v", err)
			}

			testOptions.Assert(t, CommandOutput{
				ExitCode: cmd.ProcessState.ExitCode(),
				Stdout:   stdout.String(),
				Stderr:   errout.String(),
				Stdall:   stdout.String() + errout.String(),
				Workdir:  os.DirFS(contextFolder),
			})
		})
	}
}
