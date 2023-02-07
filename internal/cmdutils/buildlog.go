package cmdutils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// region Log

var buildLogPath string

func BuildOutputToFile(projectDir string, fuzzTestNames []string) (io.Writer, error) {
	// Determine identifier for file
	var logSuffix string
	switch {
	case len(fuzzTestNames) == 0 || (len(fuzzTestNames) == 1 && fuzzTestNames[0] == ""):
		logSuffix = "all"
	case len(fuzzTestNames) > 1:
		logSuffix = strings.Join(fuzzTestNames, "_")
	default:
		logSuffix = fuzzTestNames[0]
	}
	// Make sure that calling fuzz tests in subdirs don't mess up the build log path
	logSuffix = strings.ReplaceAll(logSuffix, string(os.PathSeparator), "_")
	logFile := fmt.Sprintf("build-%s.log", logSuffix)

	logDir := filepath.Join(projectDir, ".cifuzz-build", "logs")
	// create logs dir if it doesn't exist
	err := os.MkdirAll(logDir, 0755)
	if err != nil {
		return nil, err
	}

	buildLogPath = filepath.Join(logDir, logFile)
	return os.OpenFile(buildLogPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
}

func ShouldLogBuildToFile() bool {
	return !viper.GetBool("verbose")
}

// PrintBuildLogOnStdout reads the build log file and prints it
// on stdout.
func PrintBuildLogOnStdout() error {
	fmt.Println()

	data, err := os.ReadFile(buildLogPath)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = os.Stdout.Write(data)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func GetMsgPathToBuildLog() string {
	return fmt.Sprintf("Details of the building process can be found here:\n%s\n", buildLogPath)
}
