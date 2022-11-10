package fileutil_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/util/fileutil"
)

func TestPrettifyPath(t *testing.T) {
	var filesystemRoot string
	if runtime.GOOS == "windows" {
		filesystemRoot = "C:\\"
	} else {
		filesystemRoot = "/"
	}
	cwd, err := os.Getwd()
	require.NoError(t, err)

	assert.Equal(t, filesystemRoot+filepath.Join("not", "cwd"), fileutil.PrettifyPath(filesystemRoot+filepath.Join("not", "cwd")))
	assert.Equal(t, filepath.Join("some", "dir"), fileutil.PrettifyPath(filepath.Join(cwd, "some", "dir")))
	assert.Equal(t, cwd, fileutil.PrettifyPath(cwd))
	assert.Equal(t, filepath.Dir(cwd), fileutil.PrettifyPath(filepath.Dir(cwd)))
	assert.Equal(t, filepath.Join("..some", "dir"), fileutil.PrettifyPath(filepath.Join(cwd, "..some", "dir")))
}

func TestIsBelow(t *testing.T) {
	isBelow, err := fileutil.IsBelow(filepath.Join("dir1", "dir2", "file"), filepath.Join("dir1", "dir2"))
	assert.NoError(t, err)
	assert.True(t, isBelow)

	isBelow, err = fileutil.IsBelow(filepath.Join("dir1", "dir2"), filepath.Join("dir1", "dir2"))
	assert.NoError(t, err)
	assert.True(t, isBelow)

	isBelow, err = fileutil.IsBelow("dir1", filepath.Join("dir1", "dir2"))
	assert.NoError(t, err)
	assert.False(t, isBelow)

	isBelow, err = fileutil.IsBelow(".", filepath.Join("dir1", "dir2"))
	assert.NoError(t, err)
	assert.False(t, isBelow)
}

func TestForceSymlink(t *testing.T) {
	var err error

	// Test that a symlink can be created
	sourcePath := filepath.Join(t.TempDir(), "source")
	symlinkPath := filepath.Join(t.TempDir(), "link")
	err = ForceSymlink(sourcePath, symlinkPath)
	require.NoError(t, err)
	// Check that the symlink exists
	stat, err := os.Lstat(symlinkPath)
	require.NoError(t, err)
	require.True(t, stat.Mode()&os.ModeSymlink != 0)
	// Check that the symlink points to the source
	target, err := os.Readlink(symlinkPath)
	require.NoError(t, err)
	require.Equal(t, sourcePath, target)

	// Test that a new symlink can be created in the same path
	source2Path := filepath.Join(t.TempDir(), "source2")
	err = ForceSymlink(source2Path, symlinkPath)
	require.NoError(t, err)
	// Check that the symlink exists
	stat, err = os.Lstat(symlinkPath)
	require.NoError(t, err)
	require.True(t, stat.Mode()&os.ModeSymlink != 0)
	// Check that the symlink points to the source
	target, err = os.Readlink(symlinkPath)
	require.NoError(t, err)
	require.Equal(t, source2Path, target)
}
