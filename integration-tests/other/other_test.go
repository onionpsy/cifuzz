package other

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/integration-tests/shared"
	builderPkg "code-intelligence.com/cifuzz/internal/builder"
	"code-intelligence.com/cifuzz/internal/testutil"
	"code-intelligence.com/cifuzz/pkg/finding"
	"code-intelligence.com/cifuzz/pkg/parser/libfuzzer/stacktrace"
	"code-intelligence.com/cifuzz/util/executil"
	"code-intelligence.com/cifuzz/util/fileutil"
	"code-intelligence.com/cifuzz/util/stringutil"
)

var filteredLine = regexp.MustCompile(`child process \d+ exited`)

func TestIntegration_Other_RunCoverage(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	if runtime.GOOS == "windows" {
		t.Skip("Other build systems are currently only supported on Unix")
	}
	// Install cifuzz
	testutil.RegisterTestDepOnCIFuzz()
	installDir := shared.InstallCIFuzzInTemp(t)
	cifuzz := builderPkg.CIFuzzExecutablePath(filepath.Join(installDir, "bin"))

	// Setup testdata
	dir := shared.CopyTestdataDir(t, "other")
	defer fileutil.Cleanup(dir)
	t.Logf("executing other build system integration test in %s", dir)

	cifuzzRunner := shared.CIFuzzRunner{
		CIFuzzPath:      cifuzz,
		DefaultWorkDir:  dir,
		DefaultFuzzTest: "my_fuzz_test",
	}

	expectedOutputs := []*regexp.Regexp{
		regexp.MustCompile(`^==\d*==ERROR: AddressSanitizer: heap-buffer-overflow`),
	}
	if runtime.GOOS != "windows" {
		expectedOutputs = append(expectedOutputs, regexp.MustCompile(`^SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior`))
	}

	// Check that Minijail is used (if running on Linux, because Minijail
	// is only supported on Linux)
	if runtime.GOOS == "linux" {
		expectedOutputs = append(expectedOutputs, regexp.MustCompile(`bin/minijail0`))
	}

	cifuzzRunner.Run(t, &shared.RunOptions{
		ExpectedOutputs: expectedOutputs,
	})

	// Check that the findings command lists the findings
	findings := shared.GetFindings(t, cifuzz, dir)
	// On Windows, only the ASan finding is expected, on Linux and macOS
	// both the ASan and the UBSan finding are expected.
	if runtime.GOOS == "windows" {
		require.Len(t, findings, 1)
	} else {
		require.Len(t, findings, 2)
	}
	var asanFinding *finding.Finding
	var ubsanFinding *finding.Finding
	for _, f := range findings {
		if strings.HasPrefix(f.Details, "heap-buffer-overflow") {
			asanFinding = f
		} else if strings.HasPrefix(f.Details, "undefined behavior") {
			ubsanFinding = f
		} else {
			t.Fatalf("unexpected finding: %q", f.Details)
		}
	}

	// Verify that there is an ASan finding and that it has the correct details.
	require.NotNil(t, asanFinding)
	// TODO: This check currently fails on macOS because there
	// llvm-symbolizer doesn't read debug info from object files.
	// See https://github.com/google/sanitizers/issues/207#issuecomment-136495556
	if runtime.GOOS != "darwin" {
		expectedStackTrace := []*stacktrace.StackFrame{
			{
				SourceFile:  "src/explore/explore_me.cpp",
				Line:        14,
				Column:      11,
				FrameNumber: 1,
				Function:    "exploreMe",
			},
			{
				SourceFile:  "my_fuzz_test.cpp",
				Line:        18,
				Column:      3,
				FrameNumber: 2,
				Function:    "LLVMFuzzerTestOneInputNoReturn",
			},
		}
		if runtime.GOOS == "windows" {
			// On Windows, the column is not printed
			for i := range expectedStackTrace {
				expectedStackTrace[i].Column = 0
			}
		}

		require.Equal(t, expectedStackTrace, asanFinding.StackTrace)
	}

	// Verify that there is a UBSan finding and that it has the correct details.
	if runtime.GOOS != "windows" {
		require.NotNil(t, ubsanFinding)
		// Verify that UBSan findings come with inputs.
		require.NotEmpty(t, ubsanFinding.InputFile)
		if runtime.GOOS != "darwin" {
			expectedStackTrace := []*stacktrace.StackFrame{
				{
					SourceFile:  "src/explore/explore_me.cpp",
					Line:        20,
					Column:      11,
					FrameNumber: 0,
					Function:    "exploreMe",
				},
				{
					SourceFile:  "my_fuzz_test.cpp",
					Line:        18,
					Column:      3,
					FrameNumber: 1,
					Function:    "LLVMFuzzerTestOneInputNoReturn",
				},
			}
			require.Equal(t, expectedStackTrace, ubsanFinding.StackTrace)
		}
	}

	// Test the coverage command
	createHtmlCoverageReport(t, cifuzz, dir, "my_fuzz_test")
}

func TestIntegration_Other_DetailedCoverage(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	if runtime.GOOS == "windows" {
		t.Skip("Other build systems are currently only supported on Unix")
	}
	// Install cifuzz
	testutil.RegisterTestDepOnCIFuzz()

	installDir := shared.InstallCIFuzzInTemp(t)
	cifuzz := builderPkg.CIFuzzExecutablePath(filepath.Join(installDir, "bin"))

	// Setup testdata
	dir := shared.CopyTestdataDir(t, "other")
	defer fileutil.Cleanup(dir)
	t.Logf("executing other build system coverage test in %s", dir)

	createAndVerifyLcovCoverageReport(t, cifuzz, dir, "crashing_fuzz_test")
}

func TestIntegration_Other_Bundle(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	if runtime.GOOS == "windows" {
		t.Skip("Other build systems are currently only supported on Unix")
	}
	// Install cifuzz
	testutil.RegisterTestDepOnCIFuzz()
	installDir := shared.InstallCIFuzzInTemp(t)
	cifuzz := builderPkg.CIFuzzExecutablePath(filepath.Join(installDir, "bin"))

	// Setup testdata
	dir := shared.CopyTestdataDir(t, "other")
	defer fileutil.Cleanup(dir)
	t.Logf("executing other build system integration test in %s", dir)

	// Use a different Makefile on macOS, because shared objects need
	// to be built differently there
	var args []string
	if runtime.GOOS == "darwin" {
		args = append(args, "--build-command", "make -f Makefile.darwin clean && make -f Makefile.darwin $FUZZ_TEST")
	}
	args = append(args, "my_fuzz_test")

	// Execute the bundle command
	shared.TestBundleLibFuzzer(t, dir, cifuzz, args...)
}

func createHtmlCoverageReport(t *testing.T, cifuzz string, dir string, fuzzTest string) {
	t.Helper()

	cmd := executil.Command(cifuzz, "coverage", "-v",
		"--output", fuzzTest+"-coverage",
		fuzzTest)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	t.Logf("Command: %s", strings.Join(stringutil.QuotedStrings(cmd.Args), " "))
	err := cmd.Run()
	require.NoError(t, err)

	// Check that the coverage report was created
	reportPath := filepath.Join(dir, fuzzTest+"-coverage", "src", "explore", "index.html")
	require.FileExists(t, reportPath)

	// Check that the coverage report contains coverage for the api.cpp
	// source file, but not for our headers.
	reportBytes, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	report := string(reportBytes)
	require.Contains(t, report, "explore_me.cpp")
	require.NotContains(t, report, "include/cifuzz")
}

func createAndVerifyLcovCoverageReport(t *testing.T, cifuzz string, dir string, fuzzTest string) {
	t.Helper()

	reportPath := filepath.Join(dir, fuzzTest+".lcov")

	cmd := executil.Command(cifuzz, "coverage", "-v",
		"--format=lcov",
		"--output", reportPath,
		fuzzTest)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	require.NoError(t, err)

	// Check that the coverage report was created
	require.FileExists(t, reportPath)

	// Read the report and extract all uncovered lines in the fuzz test source file.
	reportBytes, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	lcov := bufio.NewScanner(bytes.NewBuffer(reportBytes))
	isFuzzTestSource := false
	var uncoveredLines []uint
	for lcov.Scan() {
		line := lcov.Text()

		if strings.HasPrefix(line, "SF:") {
			if strings.HasSuffix(line, "/crashing_fuzz_test.c") {
				isFuzzTestSource = true
			} else {
				isFuzzTestSource = false
				assert.Fail(t, "Unexpected source file: "+line)
			}
		}

		if !isFuzzTestSource || !strings.HasPrefix(line, "DA:") {
			continue
		}
		split := strings.Split(strings.TrimPrefix(line, "DA:"), ",")
		require.Len(t, split, 2)
		if split[1] == "0" {
			lineNo, err := strconv.Atoi(split[0])
			require.NoError(t, err)
			uncoveredLines = append(uncoveredLines, uint(lineNo))
		}
	}

	assert.Subset(t, []uint{
		// Lines after the three crashes. Whether these are covered depends on implementation details of the coverage
		// instrumentation, so we conservatively assume they aren't covered.
		21, 31, 41},
		uncoveredLines)
}
