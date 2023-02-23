package e2e

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"code-intelligence.com/cifuzz/e2e-tests"
)

var helpTests = &[]e2e.Test{
	{
		Description: "help command without other arguments prints --help text",
		Command:     "help",
		Assert: func(t *testing.T, output e2e.CommandOutput) {
			assert.EqualValues(t, 0, output.ExitCode)
			assert.Equal(t, output.Stderr, "")
			assert.Contains(t, output.Stdout, "Available Commands")
		},
	},
	{
		Description: "using help args prints --help text",
		Command:     "",
		Args:        []string{"--help", "-h"},
		Assert: func(t *testing.T, output e2e.CommandOutput) {
			assert.EqualValues(t, 0, output.ExitCode)
			assert.Equal(t, output.Stderr, "")
			assert.Contains(t, output.Stdout, "Available Commands")
		},
	},
	{
		Description: "using help args prints --help text",
		Command:     "",
		Args:        []string{"--h"},
		Assert: func(t *testing.T, output e2e.CommandOutput) {
			assert.EqualValues(t, 1, output.ExitCode)
		},
	},
	{
		Description: "using help args prints --help text for subcommands",
		Command:     "bundle",
		Args:        []string{"--help"},
		Assert: func(t *testing.T, output e2e.CommandOutput) {
			assert.EqualValues(t, 0, output.ExitCode)
			assert.Equal(t, output.Stderr, "")
			assert.Contains(t, output.Stdout, "This command bundles all runtime artifacts")
		},
	},
}

func TestHelp(t *testing.T) {
	for _, test := range *helpTests {
		e2e.RunTest(t, &test)
	}
}
