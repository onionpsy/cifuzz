package run

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/internal/testutil"
	"code-intelligence.com/cifuzz/pkg/dependencies"
	"code-intelligence.com/cifuzz/pkg/log"
)

var testOut io.ReadWriter

func TestMain(m *testing.M) {
	// capture log output
	testOut = bytes.NewBuffer([]byte{})
	oldOut := log.Output
	log.Output = testOut
	viper.Set("interactive", "false")
	viper.Set("verbose", true)

	m.Run()

	log.Output = oldOut
}

func TestFail(t *testing.T) {
	_, err := cmdutils.ExecuteCommand(t, New(), os.Stdin)
	assert.Error(t, err)
}

func TestClangMissing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("clang is not needed on windows and will be provided by Visual Studio")
	}

	dependencies.MockAllDeps(t)
	// let the clang dep fail
	dependencies.OverwriteUninstalled(dependencies.GetDep(dependencies.Clang))

	// clone the example project because this command needs to parse an actual
	// project config... if there is none it will fail before the dependency check
	_, cleanup := testutil.BootstrapExampleProjectForTest("run-cmd-test", config.BuildSystemCMake)
	defer cleanup()

	_, err := cmdutils.ExecuteCommand(t, New(), os.Stdin, "my_fuzz_test")
	require.Error(t, err)

	output, err := io.ReadAll(testOut)
	require.NoError(t, err)
	fmt.Fprint(os.Stderr, string(output))
	assert.Contains(t, string(output), fmt.Sprintf(dependencies.MessageMissing, "clang"))
}

func TestLlvmSymbolizerVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("llvm-symbolizer is not needed on windows")
	}

	dependencies.MockAllDeps(t)
	dep := dependencies.GetDep(dependencies.LLVMSymbolizer)
	version := dependencies.OverwriteGetVersionWith0(dep)

	// clone the example project because this command needs to parse an actual
	// project config... if there is none it will fail before the dependency check
	_, cleanup := testutil.BootstrapExampleProjectForTest("run-cmd-test", config.BuildSystemCMake)
	defer cleanup()

	_, err := cmdutils.ExecuteCommand(t, New(), os.Stdin, "my_fuzz_test")
	require.Error(t, err)

	output, err := io.ReadAll(testOut)
	require.NoError(t, err)
	fmt.Fprint(os.Stderr, string(output))
	assert.Contains(t, string(output),
		fmt.Sprintf(dependencies.MessageVersion, "llvm-symbolizer", dep.MinVersion.String(), version))
}

func TestVisualStudioMissing(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("only needed on windows")
	}

	dependencies.MockAllDeps(t)

	dep := dependencies.GetDep(dependencies.VisualStudio)
	version := dependencies.OverwriteGetVersionWith0(dep)

	// clone the example project because this command needs to parse an actual
	// project config... if there is none it will fail before the dependency check
	_, cleanup := testutil.BootstrapExampleProjectForTest("run-cmd-test", config.BuildSystemCMake)
	defer cleanup()

	_, err := cmdutils.ExecuteCommand(t, New(), os.Stdin, "my_fuzz_test")
	require.Error(t, err)

	output, err := io.ReadAll(testOut)
	require.NoError(t, err)
	fmt.Fprint(os.Stderr, string(output))
	assert.Contains(t, string(output),
		fmt.Sprintf(dependencies.MessageVersion, "Visual Studio", dep.MinVersion.String(), version))
}
