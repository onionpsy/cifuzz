package shared

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"code-intelligence.com/cifuzz/util/stringutil"
)

type MockServer struct {
	Address           string
	ArtifactsUploaded bool
	RunStarted        bool
}

func StartMockServer(t *testing.T, projectName, artifactsName string) *MockServer {
	server := &MockServer{}

	handleListProjects := func(w http.ResponseWriter, req *http.Request) {
		_, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		_, err = fmt.Fprint(w, `{"projects": [
        {
            "name": "projects/my_fuzz_test-bac40407",
            "display_name": "my_fuzz_test",
            "location": {
                "git_path": {}
            },
            "owner_username": "users/55",
            "contact_username": "users/55"
        }]}`)
		require.NoError(t, err)
	}

	handleGetErrorDetails := func(w http.ResponseWriter, req *http.Request) {
		_, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		_, err = fmt.Fprint(w, `[
        {
          "id": "undefined behavior: .*",
          "name": "Undefined Behavior",
          "description": "An operation has been detected which is undefined by the C/C++ standard. The result will \nbe compiler dependent and is often unpredictable.",
          "severity": {
            "description": "Low",
            "score": 2
          },
          "mitigation": "Avoid all operations that cause undefined behavior as per the C/C++ standard.",
          "links": [
            {
              "description": "Undefined Behavior Sanitizer",
              "url": "https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html#available-checks"
            }
          ],
          "language": 1
        }]`)
		require.NoError(t, err)
	}

	handleUploadArtifact := func(w http.ResponseWriter, req *http.Request) {
		_, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		_, err = fmt.Fprintf(w, `{"display-name": "test-artifacts", "resource-name": "%s"}`, artifactsName)
		require.NoError(t, err)
		server.ArtifactsUploaded = true
	}

	handleCreateCampaignRun := func(w http.ResponseWriter, req *http.Request) {
		_, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		_, err = fmt.Fprintf(w, "{}")
		require.NoError(t, err)
	}

	handleUploadFinding := func(w http.ResponseWriter, req *http.Request) {
		_, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		_, err = fmt.Fprintf(w, "{}")
		require.NoError(t, err)
	}

	handleStartRun := func(w http.ResponseWriter, req *http.Request) {
		_, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		_, err = fmt.Fprintf(w, `{"name": "test-campaign-run-123"}`)
		require.NoError(t, err)
		server.RunStarted = true
	}

	handleDefault := func(w http.ResponseWriter, req *http.Request) {
		require.Fail(t, "Unexpected request", stringutil.PrettyString(req))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/projects", handleListProjects)
	mux.HandleFunc("/v2/error-details", handleGetErrorDetails)
	mux.HandleFunc(fmt.Sprintf("/v1/projects/%s/campaign_runs", projectName), handleCreateCampaignRun)
	mux.HandleFunc(fmt.Sprintf("/v1/projects/%s/findings", projectName), handleUploadFinding)
	mux.HandleFunc(fmt.Sprintf("/v2/projects/%s/artifacts/import", projectName), handleUploadArtifact)
	mux.HandleFunc(fmt.Sprintf("/v1/%s:run", artifactsName), handleStartRun)
	mux.HandleFunc("/", handleDefault)

	listener, err := net.Listen("tcp4", ":0")
	require.NoError(t, err)

	server.Address = fmt.Sprintf("http://127.0.0.1:%d", listener.Addr().(*net.TCPAddr).Port)

	go func() {
		err = http.Serve(listener, mux)
		require.NoError(t, err)
	}()

	return server
}
