package bundler

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/internal/build"
	"code-intelligence.com/cifuzz/pkg/artifact"
	"code-intelligence.com/cifuzz/util/fileutil"
)

func TestAssembleArtifactsJava_Fuzzing(t *testing.T) {
	seedCorpus, err := os.MkdirTemp("", "seed-corpus-*")
	require.NoError(t, err)
	defer fileutil.Cleanup(seedCorpus)
	tempDir, err := os.MkdirTemp("", "bundle-*")
	require.NoError(t, err)
	defer fileutil.Cleanup(tempDir)
	err = fileutil.Touch(filepath.Join(seedCorpus, "seed"))
	require.NoError(t, err)

	// The project dir path has to be absolute, but doesn't have to exist.
	projectDir, err := os.MkdirTemp(tempDir, "cifuzz-lib-*")
	require.NoError(t, err)

	fuzzTest := "com.example.FuzzTest"
	anotherFuzzTest := "com.example.AnotherFuzzTest"
	buildDir := filepath.Join(projectDir, "target")

	// we have to create a temporary directory for the runtime deps because
	// assembleArtifacts will check if the directory actually exists
	libraryPath := filepath.Join(projectDir, "lib")
	require.NoError(t, err)
	defer fileutil.Cleanup(libraryPath)
	err = os.MkdirAll(libraryPath, 0o755)
	require.NoError(t, err)
	err = fileutil.Touch(filepath.Join(libraryPath, "mylib.jar"))
	require.NoError(t, err)
	err = os.MkdirAll(filepath.Join(projectDir, "classes", "com", "example"), 0o755)
	require.NoError(t, err)
	err = os.MkdirAll(filepath.Join(projectDir, "test-classes", "com", "example"), 0o755)
	require.NoError(t, err)
	err = fileutil.Touch(filepath.Join(projectDir, "classes", "com", "example", "MyClass.class"))
	require.NoError(t, err)
	err = fileutil.Touch(filepath.Join(projectDir, "test-classes", "com", "example", "MyTest.class"))
	require.NoError(t, err)

	runtimeDeps := []string{
		// A library in the project's build directory.
		filepath.Join(libraryPath, "mylib.jar"),
		// a directory structure of class files
		filepath.Join(projectDir, "classes"),
		filepath.Join(projectDir, "test-classes"),
	}

	buildResults := []*build.Result{}
	buildResult := &build.Result{
		Name:        fuzzTest,
		BuildDir:    buildDir,
		SeedCorpus:  seedCorpus,
		Engine:      "JAVA_LIBFUZZER",
		RuntimeDeps: runtimeDeps,
		ProjectDir:  projectDir,
	}
	anotherBuildResult := &build.Result{
		Name:        anotherFuzzTest,
		BuildDir:    buildDir,
		SeedCorpus:  seedCorpus,
		Engine:      "JAVA_LIBFUZZER",
		RuntimeDeps: runtimeDeps,
		ProjectDir:  projectDir,
	}
	buildResults = append(buildResults, buildResult, anotherBuildResult)

	b := newJazzerBundler(&Opts{
		Env: []string{"FOO=foo"},
	})
	b.opts.tempDir = tempDir
	fuzzers, manifest, err := b.assembleArtifacts(buildResults)
	require.NoError(t, err)

	require.Equal(t, 2, len(fuzzers))

	expectedDeps := []string{
		// manifest.jar should always be first element in runtime paths
		filepath.Join(fuzzTest, "manifest.jar"),
		"mylib.jar",
		filepath.Join("..", "classes"),
		filepath.Join("..", "test-classes"),
	}

	fuzzer := &artifact.Fuzzer{
		Target:       buildResult.Name,
		Engine:       "JAVA_LIBFUZZER",
		ProjectDir:   buildResult.ProjectDir,
		Seeds:        "seeds",
		RuntimePaths: expectedDeps,
		EngineOptions: artifact.EngineOptions{
			Env:   b.opts.Env,
			Flags: b.opts.EngineArgs,
		},
	}
	require.Equal(t, *fuzzer, *fuzzers[0])

	m := archiveManifest{
		"mylib.jar": filepath.Join(libraryPath, "mylib.jar"),
		filepath.Join("..", "classes", "com", "example", "MyClass.class"):     filepath.Join(projectDir, "classes", "com", "example", "MyClass.class"),
		filepath.Join("..", "test-classes", "com", "example", "MyTest.class"): filepath.Join(projectDir, "test-classes", "com", "example", "MyTest.class"),
	}
	require.Equal(t, m, manifest)
}
