package e2e

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"code-intelligence.com/cifuzz/e2e-tests"
)

var initTests = &[]e2e.Test{
	{
		Description:  "init command in empty project succeeds and creates a config file",
		Command:      "init",
		SampleFolder: []string{"empty"},
		Assert: func(t *testing.T, output e2e.CommandOutput) {
			assert.EqualValues(t, 0, output.ExitCode)
			assert.Contains(t, output.Stdall, "Configuration saved in cifuzz.yaml")
		},
	},
}

func TestInit(t *testing.T) {
	for _, test := range *initTests {
		e2e.RunTest(t, &test)
	}
}
