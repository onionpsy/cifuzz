package shared

import (
	"bufio"
	"context"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"code-intelligence.com/cifuzz/util/executil"
)

type CIFuzzRunner struct {
	CIFuzzPath      string
	DefaultWorkDir  string
	DefaultFuzzTest string
}

type CommandOptions struct {
	WorkDir string
	Env     []string
	Args    []string
}

// Command runs "cifuzz <command> <args>" and returns stderr output
func (r *CIFuzzRunner) Command(t *testing.T, command string, opts *CommandOptions) []string {
	t.Helper()

	if opts == nil {
		opts = &CommandOptions{}
	}

	var args []string
	// Empty command means that the root command should be executed
	if command != "" {
		args = append(args, command)
	}
	args = append(args, opts.Args...)

	if opts.WorkDir == "" {
		opts.WorkDir = r.DefaultWorkDir
	}

	cmd := executil.Command(r.CIFuzzPath, args...)
	cmd.Dir = opts.WorkDir
	stderrPipe, err := cmd.StderrTeePipe(os.Stderr)
	require.NoError(t, err)
	defer func() {
		err = stderrPipe.Close()
		require.NoError(t, err)
	}()

	t.Logf("Command: %s", cmd.String())
	err = cmd.Run()
	require.NoError(t, err)

	scanner := bufio.NewScanner(stderrPipe)
	var stdErrOutput []string
	for scanner.Scan() {
		stdErrOutput = append(stdErrOutput, scanner.Text())
	}

	return stdErrOutput
}

func FilterForInstructions(lines []string) []string {
	var linesToAdd []string
	for _, line := range lines {
		if strings.HasPrefix(line, "    ") {
			linesToAdd = append(linesToAdd, strings.TrimSpace(line))
		}
	}
	return linesToAdd
}

// CommandWithFilterForInstructions runs "cifuzz <command> <args>" and
// returns any indented lines which the command prints to stderr
// (which we expect to be lines which should be added to some source or config file).
func (r *CIFuzzRunner) CommandWithFilterForInstructions(t *testing.T, command string, opts *CommandOptions) []string {
	allLines := r.Command(t, command, opts)
	return FilterForInstructions(allLines)
}

type RunOptions struct {
	FuzzTest string
	WorkDir  string
	Env      []string
	Args     []string

	ExpectedOutputs              []*regexp.Regexp
	UnexpectedOutput             *regexp.Regexp
	TerminateAfterExpectedOutput bool
	ExpectError                  bool
}

func (r *CIFuzzRunner) Run(t *testing.T, opts *RunOptions) {
	t.Helper()

	if opts.Env == nil {
		opts.Env = os.Environ()
	}

	if opts.WorkDir == "" {
		opts.WorkDir = r.DefaultWorkDir
	}

	if opts.FuzzTest == "" {
		opts.FuzzTest = r.DefaultFuzzTest
	}

	runCtx, closeRunCtx := context.WithCancel(context.Background())
	defer closeRunCtx()
	args := append(
		[]string{
			"run", "-v", opts.FuzzTest,
			"--no-notifications",
			"--engine-arg=-seed=1",
			"--engine-arg=-runs=1000000",
			"--interactive=false",
		},
		opts.Args...,
	)

	cmd := executil.CommandContext(
		runCtx,
		r.CIFuzzPath,
		args...,
	)
	cmd.Dir = opts.WorkDir
	cmd.Env = opts.Env
	stdoutPipe, err := cmd.StdoutTeePipe(os.Stdout)
	require.NoError(t, err)
	stderrPipe, err := cmd.StderrTeePipe(os.Stderr)
	require.NoError(t, err)

	// Terminate the cifuzz process when we receive a termination signal
	// (else the test won't stop).
	TerminateOnSignal(t, cmd)

	t.Logf("Command: %s", cmd.String())
	err = cmd.Start()
	require.NoError(t, err)

	waitErrCh := make(chan error)
	// Wait for the command to exit in a go routine, so that below
	// we can cancel waiting when the context is done
	go func() {
		waitErrCh <- cmd.Wait()
	}()

	// Check that the output contains the expected output
	outputChecker := outputChecker{
		mutex:                        &sync.Mutex{},
		lenExpectedOutputs:           len(opts.ExpectedOutputs),
		numSeenExpectedOutputs:       0,
		expectedOutputs:              opts.ExpectedOutputs,
		unexpectedOutput:             opts.UnexpectedOutput,
		terminateAfterExpectedOutput: opts.TerminateAfterExpectedOutput,
		termationFunc: func() {
			err := cmd.TerminateProcessGroup()
			require.NoError(t, err)
		},
	}

	routines := errgroup.Group{}
	routines.Go(func() error {
		// cifuzz progress messages go to stdout.
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			outputChecker.checkOutput(t, scanner.Text())
		}
		err = stdoutPipe.Close()
		require.NoError(t, err)
		return nil
	})

	routines.Go(func() error {
		// Fuzzer output goes to stderr.
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			outputChecker.checkOutput(t, scanner.Text())
		}
		err = stderrPipe.Close()
		require.NoError(t, err)
		return nil
	})

	select {
	case waitErr := <-waitErrCh:

		err = routines.Wait()
		require.NoError(t, err)

		if outputChecker.hasCalledTerminationFunc && executil.IsTerminatedExitErr(waitErr) {
			return
		}
		if opts.ExpectError {
			require.Error(t, waitErr)
		} else {
			require.NoError(t, waitErr)
		}
	case <-runCtx.Done():
		require.NoError(t, runCtx.Err())
	}

	require.True(t, outputChecker.hasSeenExpectedOutputs, "Did not see %q in fuzzer output", opts.ExpectedOutputs)
}

type outputChecker struct {
	mutex                        *sync.Mutex
	lenExpectedOutputs           int
	numSeenExpectedOutputs       int
	expectedOutputs              []*regexp.Regexp
	unexpectedOutput             *regexp.Regexp
	terminateAfterExpectedOutput bool
	termationFunc                func()
	hasSeenExpectedOutputs       bool
	hasCalledTerminationFunc     bool
}

func (c *outputChecker) checkOutput(t *testing.T, line string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.unexpectedOutput != nil {
		if c.unexpectedOutput.MatchString(line) {
			require.FailNowf(t, "Unexpected output", "Seen unexpected output %v in line: %s", c.unexpectedOutput.String(), line)
		}
	}

	var remainingExpectedOutputs []*regexp.Regexp
	for _, expectedOutput := range c.expectedOutputs {
		if expectedOutput.MatchString(line) {
			c.numSeenExpectedOutputs += 1
		} else {
			remainingExpectedOutputs = append(remainingExpectedOutputs, expectedOutput)
		}
	}
	c.expectedOutputs = remainingExpectedOutputs

	if c.numSeenExpectedOutputs == c.lenExpectedOutputs {
		c.hasSeenExpectedOutputs = true
		if c.terminateAfterExpectedOutput {
			c.hasCalledTerminationFunc = true
			c.termationFunc()
		}
	}

}
