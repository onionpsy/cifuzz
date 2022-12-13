package names

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeterminsticName(t *testing.T) {
	assert.Equal(t, "gracious_camel", GetDeterministicName([]byte("fc75")))
	assert.Equal(t, "obnoxious_tortoise", GetDeterministicName([]byte("fc7598c04e2ffdc36c3ff70428fd98912ffb07a8")))
	assert.Equal(t, "observing_deer", GetDeterministicName([]byte("")))
}
