package stringutil

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSplitAfterNBytes(t *testing.T) {

	type test struct {
		desc  string
		input string
		size  int
	}

	tests := []test{
		{desc: "all chunks same size", input: "ABCDEF", size: 2},
		{desc: "last chunk smaller than size #1", input: "ABCDEFG", size: 2},
		{desc: "last chunk smaller than size #2", input: "ABCDEFG", size: 4},
		{desc: "size = input", input: "ABCD", size: 4},
		{desc: "size bigger than input", input: "AB", size: 5},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			chunks := SplitAfterNBytes(tc.input, tc.size)
			assert.Equal(t, strings.Join(chunks, ""), tc.input)
			for i, chunk := range chunks {
				// the last chunk can be smaller than n if
				// the length of the input is not divisible
				// by the chunk size without a remainder
				if i == len(chunks)-1 && len(tc.input)%tc.size != 0 {
					assert.Equal(t, len(tc.input)%tc.size, len(chunk))
				} else {
					assert.Len(t, chunk, tc.size)
				}

			}
		})
	}
}

func TestSplitAfterNBytes_EmptyString(t *testing.T) {
	result := SplitAfterNBytes("", 3)
	assert.Empty(t, result)
}

func TestSplitAfterNBytes_InvalidSize(t *testing.T) {
	assert.Panics(t, func() { SplitAfterNBytes("AB", 0) })
}
