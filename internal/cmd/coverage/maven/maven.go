package maven

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/internal/build/maven"
	"code-intelligence.com/cifuzz/internal/cmd/coverage/summary"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/coverage"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/pkg/runfiles"
	"code-intelligence.com/cifuzz/util/executil"
	"code-intelligence.com/cifuzz/util/stringutil"
)

type MavenCoverageGenerator struct {
	OutputFormat string
	OutputPath   string
	FuzzTest     string
	ProjectDir   string

	Parallel maven.ParallelOptions

	StdOut io.Writer
	StdErr io.Writer

	runfilesFinder runfiles.RunfilesFinder
}

func (cov *MavenCoverageGenerator) runMavenCommand(args []string) error {
	mavenCmd, err := cov.runfilesFinder.MavenPath()
	if err != nil {
		return err
	}

	cmdArgs := []string{mavenCmd}
	cmdArgs = append(cmdArgs, args...)

	cmd := executil.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Dir = cov.ProjectDir
	cmd.Stdout = cov.StdOut
	cmd.Stderr = cov.StdErr
	log.Debugf("Running maven command: %s", strings.Join(stringutil.QuotedStrings(cmd.Args), " "))

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
		// It's expected that maven might fail due to user configuration,
		// so we print the error without the stack trace.
		err = cmdutils.WrapExecError(errors.WithStack(err), cmd.Cmd)
		log.Error(err)
		return cmdutils.ErrSilent
	}
	return nil
}

func (cov *MavenCoverageGenerator) Generate() (string, error) {
	// ensure a finder is set
	if cov.runfilesFinder == nil {
		cov.runfilesFinder = runfiles.Finder
	}

	mavenTestArgs := []string{
		// Maven tests fail if fuzz tests fail, so we ignore the error here.
		// We still want to generate the coverage report, so use this flag:
		"-Dmaven.test.failure.ignore=true",
		"-Djazzer.hooks=false",
		"-Pcifuzz",
		fmt.Sprintf("-Dtest=%s", cov.FuzzTest),
		"test",
	}
	if cov.Parallel.Enabled {
		mavenTestArgs = append(mavenTestArgs, "-T")
		if cov.Parallel.NumJobs != 0 {
			mavenTestArgs = append(mavenTestArgs, fmt.Sprint(cov.Parallel.NumJobs))
		} else {
			// Use one thread per cpu core
			mavenTestArgs = append(mavenTestArgs, "1C")
		}
	}
	err := cov.runMavenCommand(mavenTestArgs)
	if err != nil {
		return "", err
	}

	if cov.OutputPath == "" {
		// We using the .cifuzz-build directory
		// because the build directory is unknown at this point
		cov.OutputPath = filepath.Join(cov.ProjectDir, ".cifuzz-build", "report")
	}
	mavenReportArgs := []string{
		"-Pcifuzz",
		"jacoco:report",
		fmt.Sprintf("-Dcifuzz.report.output=%s", cov.OutputPath),
	}

	if cov.OutputFormat == coverage.FormatJacocoXML {
		mavenReportArgs = append(mavenReportArgs, "-Dcifuzz.report.format=XML")
	} else {
		mavenReportArgs = append(mavenReportArgs, "-Dcifuzz.report.format=XML,HTML")
	}

	err = cov.runMavenCommand(mavenReportArgs)
	if err != nil {
		return "", err
	}

	summary.ParseJacocoXML(filepath.Join(cov.OutputPath, "jacoco.xml")).PrintTable(cov.StdErr)

	if cov.OutputFormat == coverage.FormatJacocoXML {
		return filepath.Join(cov.OutputPath, "jacoco.xml"), nil
	}

	return filepath.Join(cov.OutputPath, "index.html"), nil
}
