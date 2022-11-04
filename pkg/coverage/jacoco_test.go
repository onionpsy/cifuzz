package coverage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/internal/testutil"
)

var testDir string
var reportPath string

func TestMain(m *testing.M) {
	testDir, cleanup := testutil.ChdirToTempDir("llvm-coverage-gen")
	defer cleanup()

	reportPath = filepath.Join(testDir, "jacoco.xml")

	m.Run()
}

func TestParseJacoco(t *testing.T) {
	reportData := `
<report name="maven-example">
    <package name="com/example">
        <sourcefile name="ExploreMe.java">
            <counter type="LINE" missed="100" covered="100"/>
            <counter type="BRANCH" missed="22" covered="1"/>
            <counter type="METHOD" missed="19" covered="2"/>
        </sourcefile>
        <sourcefile name="App.java">
            <counter type="LINE" missed="0" covered="50"/>
            <counter type="BRANCH" missed="1" covered="9"/>
            <counter type="METHOD" missed="0" covered="1"/>
        </sourcefile>
    </package>
</report>
`
	err := os.WriteFile(reportPath, []byte(reportData), 0644)
	require.NoError(t, err)
	summary := ParseJacocoXML(reportPath)

	assert.Len(t, summary.Files, 2)
	assert.Equal(t, 3, summary.Total.FunctionsHit)
	assert.Equal(t, 22, summary.Total.FunctionsFound)
	assert.Equal(t, 10, summary.Total.BranchesHit)
	assert.Equal(t, 33, summary.Total.BranchesFound)
	assert.Equal(t, 150, summary.Total.LinesHit)
	assert.Equal(t, 250, summary.Total.LinesFound)

	assert.Equal(t, 2, summary.Files[0].Coverage.FunctionsHit)
	assert.Equal(t, 21, summary.Files[0].Coverage.FunctionsFound)
	assert.Equal(t, 1, summary.Files[0].Coverage.BranchesHit)
	assert.Equal(t, 23, summary.Files[0].Coverage.BranchesFound)
	assert.Equal(t, 100, summary.Files[0].Coverage.LinesHit)
	assert.Equal(t, 200, summary.Files[0].Coverage.LinesFound)

	assert.Equal(t, 1, summary.Files[1].Coverage.FunctionsHit)
	assert.Equal(t, 1, summary.Files[1].Coverage.FunctionsFound)
	assert.Equal(t, 9, summary.Files[1].Coverage.BranchesHit)
	assert.Equal(t, 10, summary.Files[1].Coverage.BranchesFound)
	assert.Equal(t, 50, summary.Files[1].Coverage.LinesHit)
	assert.Equal(t, 50, summary.Files[1].Coverage.LinesFound)
}

func TestParseJacoco_Empty(t *testing.T) {
	err := os.WriteFile(reportPath, []byte{}, 0644)
	require.NoError(t, err)
	summary := ParseJacocoXML(reportPath)

	assert.Len(t, summary.Files, 0)
	assert.Empty(t, summary.Total.BranchesFound)
	assert.Empty(t, summary.Total.LinesFound)
	assert.Empty(t, summary.Total.FunctionsFound)
}
