package cmdutils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// region Log

var buildLogPath string

func BuildOutputToFile(projectDir string, fuzzTestNames []string) (io.Writer, error) {
	// Handle multiple fuzz tests
	fuzzTestName := fuzzTestNames[0]
	if len(fuzzTestNames) > 1 {
		for i := 1; i < len(fuzzTestNames); i++ {
			fuzzTestName += "_" + fuzzTestNames[i]
		}
	}

	logDir := filepath.Join(projectDir, ".cifuzz-build", "logs")
	// create logs dir if it doesn't exist
	err := os.MkdirAll(logDir, 0755)
	if err != nil {
		return nil, err
	}

	logFile := fmt.Sprintf("build-%s.log", fuzzTestName)
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
