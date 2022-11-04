package generator

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"code-intelligence.com/cifuzz/internal/build/gradle"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/pkg/coverage"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/runfiles"
	"code-intelligence.com/cifuzz/util/executil"
	"code-intelligence.com/cifuzz/util/stringutil"
)

type GradleCoverageGenerator struct {
	OutputFormat string
	OutputPath   string
	FuzzTest     string
	ProjectDir   string

	Parallel gradle.ParallelOptions

	StdOut io.Writer
	StdErr io.Writer

	runfilesFinder runfiles.RunfilesFinder
}

func (cov *GradleCoverageGenerator) runGradleCommand(args []string) error {
	gradleCmd, err := gradle.GetGradleCommand(cov.ProjectDir)
	if err != nil {
		return err
	}

	initScript, err := runfiles.Finder.GradleInitScriptPath()
	if err != nil {
		return err
	}

	cmdArgs := []string{gradleCmd, "-I", initScript}
	cmdArgs = append(cmdArgs, args...)

	cmd := executil.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Dir = cov.ProjectDir
	cmd.Stdout = cov.StdOut
	cmd.Stderr = cov.StdErr
	log.Debugf("Running gradle command: %s", strings.Join(stringutil.QuotedStrings(cmd.Args), " "))

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	go func() {
		_ = <-sigs
		err = cmd.TerminateProcessGroup()
		if err != nil {
			log.Error(err, err.Error())
		}
	}()

	err = cmd.Run()
	if err != nil {
		// It's expected that gradle might fail due to user configuration,
		// so we print the error without the stack trace.
		err = cmdutils.WrapExecError(err, cmd.Cmd)
		log.Error(err)
		return cmdutils.ErrSilent
	}
	return nil
}

func (cov *GradleCoverageGenerator) Generate() (string, error) {
	// ensure a finder is set
	if cov.runfilesFinder == nil {
		cov.runfilesFinder = runfiles.Finder
	}

	gradleTestArgs := []string{
		"cifuzzTest",
		fmt.Sprintf("-Pcifuzz.fuzztest=%s", cov.FuzzTest),
	}
	if cov.Parallel.Enabled {
		gradleTestArgs = append(gradleTestArgs, "--parallel")
	}
	err := cov.runGradleCommand(gradleTestArgs)
	if err != nil {
		return "", err
	}

	if cov.OutputPath == "" {
		buildDir, err := gradle.GetBuildDirectory(cov.ProjectDir)
		if err != nil {
			return "", err
		}
		cov.OutputPath = filepath.Join(buildDir, "reports", "cifuzz")
	}
	gradleReportArgs := []string{
		"cifuzzReport",
		fmt.Sprintf("-Pcifuzz.report.output=%s", cov.OutputPath),
	}
	err = cov.runGradleCommand(gradleReportArgs)
	if err != nil {
		return "", err
	}

	coverage.ParseJacocoXML(filepath.Join(cov.OutputPath, "jacoco.xml")).PrintTable(cov.StdErr)

	return filepath.Join(cov.OutputPath, "html", "index.html"), nil
}
