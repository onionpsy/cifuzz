package e2e

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/assert"

	"code-intelligence.com/cifuzz/e2e-tests"
)

var nodeInitTests = &[]e2e.TestCase{
	{
		Description:  "init command in Node.js project without prerelease flag prints error",
		Command:      "init",
		SampleFolder: []string{"nodejs"},
		Assert: func(t *testing.T, output e2e.CommandOutput) {
			assert.EqualValues(t, 1, output.ExitCode)
			assert.Contains(t, output.Stderr, "cifuzz does not support NodeJS projects yet.")
			matches, _ := fs.Glob(output.Workdir, "cifuzz.yaml")
			assert.Len(t, matches, 0, "There shouldn't be a cifuzz.yaml config")
		},
	},
	{
		Description:  "init command in Node.js project with prerelease flag succeeds and creates a config file",
		Command:      "init",
		Environment:  []string{"CIFUZZ_PRERELEASE=true"},
		SampleFolder: []string{"nodejs"},
		Assert: func(t *testing.T, output e2e.CommandOutput) {
			assert.EqualValues(t, 0, output.ExitCode)
			assert.Contains(t, output.Stdall, "To use jazzer.js, add a dev-dependency to @jazzer.js/jest-runner")
			assert.Contains(t, output.Stdall, "Configuration saved in cifuzz.yaml")
			matches, _ := fs.Glob(output.Workdir, "cifuzz.yaml")
			assert.Len(t, matches, 1, "There should be a cifuzz.yaml config")
		},
	},
}

func TestInitForNodejs(t *testing.T) {
	e2e.RunTests(t, *nodeInitTests)
}
