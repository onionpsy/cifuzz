package regexutil

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// cmakeFuzzTestFileNamePattern
// not imported directly due to import cycle
var testRegex = regexp.MustCompile(`add_fuzz_test\((?P<fuzzTest>[a-zA-Z0-9_.+=,@~-]+)\s(?P<file>[a-zA-Z0-9_.+=,@~-]+)\)`)

func TestFindAllNamedGroupsMatches(t *testing.T) {
	text := `
add_fuzz_test(my_fuzz_test my_fuzz_test.cpp)
add_fuzz_test(my_fuzz_test2 my_fuzz_test2.cpp)
add_fuzz_test(my_fuzz_test3 my_fuzz_test3.cpp)
`
	expected := []map[string]string{
		{"file": "my_fuzz_test.cpp", "fuzzTest": "my_fuzz_test"},
		{"file": "my_fuzz_test2.cpp", "fuzzTest": "my_fuzz_test2"},
		{"file": "my_fuzz_test3.cpp", "fuzzTest": "my_fuzz_test3"},
	}
	result, found := FindAllNamedGroupsMatches(testRegex, text)
	require.True(t, found)
	require.Equal(t, expected, result)
}

func TestFindNamedGroupsMatch(t *testing.T) {
	text := `
add_fuzz_test(my_fuzz_test my_fuzz_test.cpp)
add_fuzz_test(my_fuzz_test2 my_fuzz_test2.cpp)
add_fuzz_test(my_fuzz_test3 my_fuzz_test3.cpp)
`
	expected := map[string]string{
		"file": "my_fuzz_test.cpp", "fuzzTest": "my_fuzz_test",
	}
	result, found := FindNamedGroupsMatch(testRegex, text)
	require.True(t, found)
	require.Equal(t, expected, result)
}
