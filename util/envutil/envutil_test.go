package envutil

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAppendToPathList(t *testing.T) {
	// Check values successfully added
	require.Equal(t, "foo", AppendToPathList("", "foo"))
	require.Equal(t, "foo"+sep+"bar", AppendToPathList("foo", "bar"))
	require.Equal(t, "foo"+sep+"bar"+sep+"baz", AppendToPathList("foo"+sep+"bar", "baz"))
	// Check no duplicates added
	require.Equal(t, "foo", AppendToPathList("foo", "foo"))
	require.Equal(t, "foo"+sep+"bar", AppendToPathList("foo"+sep+"bar", "foo"))
	require.Equal(t, "foo"+sep+"bar", AppendToPathList("foo"+sep+"bar", "bar"))
	// Check no empty values added
	require.Equal(t, "foo", AppendToPathList("foo"))
	require.Equal(t, "foo", AppendToPathList("foo", ""))
	require.Equal(t, "foo"+sep+"bar", AppendToPathList("foo"+sep+"bar", ""))
	// Check multiple values added
	require.Equal(t, "foo"+sep+"bar", AppendToPathList("", "foo", "bar"))
	require.Equal(t, "foo"+sep+"bar"+sep+"baz", AppendToPathList("foo", "bar", "baz"))
}

func TestSetenv(t *testing.T) {
	var env []string

	env, err := Setenv(env, "foo", "foo")
	require.NoError(t, err)
	require.Equal(t, env, []string{"foo=foo"})

	env, err = Setenv(env, "foo", "bar")
	require.NoError(t, err)
	require.Equal(t, env, []string{"foo=bar"})

	env, err = Setenv(env, "bao", "bab")
	require.NoError(t, err)
	require.Equal(t, env, []string{"foo=bar", "bao=bab"})
}

func TestGetenv(t *testing.T) {
	var val string

	val = Getenv([]string{}, "foo")
	require.Equal(t, val, "")

	val = Getenv([]string{"foo=bar"}, "foo")
	require.Equal(t, val, "bar")
}

func TestCopy(t *testing.T) {
	src := []string{"FOO=foo", "BAR=bar"}
	dst := []string{"BAO=bab", "BAR=overwrite me"}
	res, err := Copy(dst, src)
	require.NoError(t, err)
	require.Equal(t, []string{"BAO=bab", "BAR=bar", "FOO=foo"}, res)
}

func TestGetEnvWithPathSubstring(t *testing.T) {
	value := filepath.Join("foo", "bar")
	env := []string{"foo=" + value}

	// Check with valid substring
	res := GetEnvWithPathSubstring(env, "foo", "bar")
	require.Equal(t, value, res)

	// Check with invalid substring
	res = GetEnvWithPathSubstring(env, "foo", "foo")
	require.Equal(t, "", res)
}
