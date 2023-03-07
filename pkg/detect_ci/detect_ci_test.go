package detect_ci

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Some samples
var envvarsAndExpected = [][]string{
	{"CI", "custom"},
	{"GERRIT_PROJECT", "gerrit"},
	{"GITHUB_ACTIONS", "github-actions"},
	{"TRAVIS", "travis-ci"},
}

func TestIsCI(t *testing.T) {
	os.Clearenv()
	assert.False(t, IsCI())
	for _, envvarAndExpected := range envvarsAndExpected {
		os.Setenv(envvarAndExpected[0], "true")

		assert.True(t, IsCI())
		assert.Equal(t, envvarAndExpected[1], CIName())

		os.Unsetenv(envvarAndExpected[0])
		assert.False(t, IsCI())
	}
}
