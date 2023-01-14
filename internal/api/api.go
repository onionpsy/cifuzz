package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"golang.org/x/term"

	"code-intelligence.com/cifuzz/internal/cmd/remote-run/progress"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/pkg/finding"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/stringutil"
)

// APIError is returned when a REST request returns a status code other
// than 200 OK
type APIError struct {
	err        error
	StatusCode int
}

func (e APIError) Error() string {
	return e.err.Error()
}

func (e APIError) Format(s fmt.State, verb rune) {
	if formatter, ok := e.err.(fmt.Formatter); ok {
		formatter.Format(s, verb)
	} else {
		_, _ = io.WriteString(s, e.Error())
	}
}

func (e APIError) Unwrap() error {
	return e.err
}

func responseToAPIError(resp *http.Response) error {
	msg := resp.Status
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &APIError{StatusCode: resp.StatusCode, err: errors.New(msg)}
	}
	apiResp := struct {
		Code    int
		Message string
	}{}
	err = json.Unmarshal(body, &apiResp)
	if err != nil {
		return &APIError{StatusCode: resp.StatusCode, err: errors.Errorf("%s: %s", msg, string(body))}
	}
	return &APIError{StatusCode: resp.StatusCode, err: errors.Errorf("%s: %s", msg, apiResp.Message)}
}

type APIClient struct {
	Server string
}

var FeaturedProjectsOrganization = "organizations/1"

type ProjectBody struct {
	Project Project `json:"project"`
}

type Project struct {
	Name                  string `json:"name"`
	DisplayName           string `json:"display_name"`
	OwnerOrganizationName string `json:"owner_organization_name,omitempty"`
}

type ProjectResponse struct {
	Name     string   `json:"name"`
	Done     bool     `json:"done"`
	Response Response `json:"response"`
}

type Response struct {
	Type          string   `json:"@type"`
	Name          string   `json:"name"`
	DisplayName   string   `json:"display_name"`
	Location      Location `json:"location"`
	OwnerUsername string   `json:"owner_username"`
}

type Location struct {
	GitPath GitPath `json:"git_path"`
}

type GitPath struct{}

type Artifact struct {
	DisplayName  string `json:"display-name"`
	ResourceName string `json:"resource-name"`
}

type CampaignRunBody struct {
	CampaignRun CampaignRun `json:"campaign_run"`
}

type CampaignRun struct {
	Name        string       `json:"name"`
	DisplayName string       `json:"display_name"`
	Campaign    Campaign     `json:"campaign"`
	Runs        []FuzzingRun `json:"runs"`
	Status      string       `json:"status"`
	Timestamp   string       `json:"timestamp"`
}

type Campaign struct {
	MaxRunTime string `json:"max_run_time"`
}

type FuzzingRun struct {
	Name                    string                  `json:"name"`
	DisplayName             string                  `json:"display_name"`
	Status                  string                  `json:"status"`
	FuzzerRunConfigurations FuzzerRunConfigurations `json:"fuzzer_run_configurations"`
	FuzzTargetConfig        FuzzTargetConfig        `json:"fuzz_target_config"`
}

type FuzzTargetConfig struct {
	Name string `json:"name"`
	CAPI CAPI   `json:"c_api"`
}

type CAPI struct {
	API API `json:"api"`
}

type API struct {
	RelativePath string `json:"relative_path"`
}

type FuzzerRunConfigurations struct {
	Engine       string `json:"engine"`
	NumberOfJobs int64  `json:"number_of_jobs"`
}

type FindingsBody struct {
	Findings []Finding `json:"findings"`
}

type Finding struct {
	Name        string      `json:"name"`
	DisplayName string      `json:"display_name"`
	FuzzTarget  string      `json:"fuzz_target"`
	FuzzingRun  string      `json:"fuzzing_run"`
	CampaignRun string      `json:"campaign_run"`
	ErrorReport ErrorReport `json:"error_report"`
	Timestamp   string      `json:"timestamp"`
}

type ErrorReport struct {
	Logs    []string `json:"logs"`
	Details string   `json:"details"`
}

func (client *APIClient) UploadBundle(path string, projectName string, token string) (*Artifact, error) {
	signalHandlerCtx, cancelSignalHandler := context.WithCancel(context.Background())
	routines, routinesCtx := errgroup.WithContext(context.Background())

	// Cancel the routines context when receiving a termination signal
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	routines.Go(func() error {
		select {
		case <-signalHandlerCtx.Done():
			return nil
		case s := <-sigs:
			log.Warnf("Received %s", s.String())
			return cmdutils.NewSignalError(s.(syscall.Signal))
		}
	})

	// Use a pipe to avoid reading the artifacts into memory at once
	r, w := io.Pipe()
	m := multipart.NewWriter(w)

	// Write the artifacts to the pipe
	routines.Go(func() error {
		defer w.Close()
		defer m.Close()

		part, err := m.CreateFormFile("fuzzing-artifacts", path)
		if err != nil {
			return errors.WithStack(err)
		}

		fileInfo, err := os.Stat(path)
		if err != nil {
			return errors.WithStack(err)
		}

		f, err := os.Open(path)
		if err != nil {
			return errors.WithStack(err)
		}
		defer f.Close()

		var reader io.Reader
		printProgress := term.IsTerminal(int(os.Stdout.Fd()))
		if printProgress {
			fmt.Println("Uploading...")
			reader = progress.NewReader(f, fileInfo.Size(), "Upload complete")
		} else {
			reader = f
		}

		_, err = io.Copy(part, reader)
		return errors.WithStack(err)
	})

	// Send a POST request with what we read from the pipe. The request
	// gets cancelled with the routines context is cancelled, which
	// happens if an error occurs in the io.Copy above or the user if
	// cancels the operation.
	var body []byte
	routines.Go(func() error {
		defer r.Close()
		defer cancelSignalHandler()
		url := fmt.Sprintf("%s/v2/%s/artifacts/import", client.Server, projectName)
		req, err := http.NewRequestWithContext(routinesCtx, "POST", url, r)
		if err != nil {
			return errors.WithStack(err)
		}
		req.Header.Set("Content-Type", m.FormDataContentType())
		req.Header.Add("Authorization", "Bearer "+token)

		httpClient := &http.Client{}
		resp, err := httpClient.Do(req)
		if err != nil {
			return errors.WithStack(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return responseToAPIError(resp)
		}

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})

	err := routines.Wait()
	if err != nil {
		return nil, err
	}

	artifact := &Artifact{}
	err = json.Unmarshal(body, artifact)
	if err != nil {
		err = errors.WithStack(err)
		log.Errorf(err, "Failed to parse response from upload bundle API call: %s", err.Error())
		return nil, cmdutils.WrapSilentError(err)
	}

	return artifact, nil
}

func (client *APIClient) StartRemoteFuzzingRun(artifact *Artifact, token string) (string, error) {
	resp, err := client.sendRequest("POST", fmt.Sprintf("v1/%s:run", artifact.ResourceName), nil, token)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", responseToAPIError(resp)
	}

	// Get the campaign run name from the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.WithStack(err)
	}
	var objmap map[string]json.RawMessage
	err = json.Unmarshal(body, &objmap)
	if err != nil {
		return "", errors.WithStack(err)
	}
	campaignRunNameJSON, ok := objmap["name"]
	if !ok {
		err := errors.Errorf("Server response doesn't include run name: %v", stringutil.PrettyString(objmap))
		log.Error(err)
		return "", cmdutils.WrapSilentError(err)
	}
	var campaignRunName string
	err = json.Unmarshal(campaignRunNameJSON, &campaignRunName)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return campaignRunName, nil
}

func (client *APIClient) sendRequest(method string, endpoint string, body io.Reader, token string) (*http.Response, error) {
	url := fmt.Sprintf("%s/%s", client.Server, endpoint)
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	req.Header.Add("Authorization", "Bearer "+token)

	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return resp, nil
}

func (client *APIClient) ListProjects(token string) ([]*Project, error) {
	resp, err := client.sendRequest("GET", "v1/projects", nil, token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, responseToAPIError(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var objmap map[string]json.RawMessage
	err = json.Unmarshal(body, &objmap)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var projects []*Project
	err = json.Unmarshal(objmap["projects"], &projects)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Filter out featured projects
	var filteredProjects []*Project
	for _, p := range projects {
		if p.OwnerOrganizationName == FeaturedProjectsOrganization {
			continue
		}
		filteredProjects = append(filteredProjects, p)
	}

	return filteredProjects, nil
}

func (client *APIClient) CreateProject(name string, token string) (*Project, error) {
	projectBody := &ProjectBody{
		Project: Project{
			DisplayName: name,
		},
	}

	body, err := json.Marshal(projectBody)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	resp, err := client.sendRequest("POST", "v1/projects", bytes.NewReader(body), token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, responseToAPIError(resp)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var projectResponse ProjectResponse
	err = json.Unmarshal(body, &projectResponse)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	projectBody.Project.Name = projectResponse.Response.Name

	return &projectBody.Project, nil
}

// CreateCampaignRun creates a new campaign run for the given project and
// returns the name of the campaign and fuzzing run. The campaign and fuzzing
// run name is used to identify the campaign run in the API for consecutive
// calls.
func (client *APIClient) CreateCampaignRun(project string, token string, fuzzTarget string, numBuildJobs uint) (string, string, error) {
	// generate a short random string to use as the campaign run name
	randBytes := make([]byte, 8)
	_, err := rand.Read(randBytes)
	if err != nil {
		return "", "", errors.WithStack(err)
	}

	fuzzingRun := FuzzingRun{
		Name:        project + "/fuzzing_runs/cifuzz-fuzzing-run-" + hex.EncodeToString(randBytes),
		DisplayName: "cifuzz-fuzzing-run",
		Status:      "SUCCEEDED",
		FuzzerRunConfigurations: FuzzerRunConfigurations{
			Engine:       "LIBFUZZER",
			NumberOfJobs: 4,
		},
		FuzzTargetConfig: FuzzTargetConfig{
			Name: project + "/fuzz_targets/" + fuzzTarget,
			CAPI: CAPI{
				API: API{
					RelativePath: fuzzTarget,
				},
			},
		},
	}
	campaignRun := CampaignRun{
		Name:        project + "/campaign_runs/cifuzz-campaign-run-" + hex.EncodeToString(randBytes),
		DisplayName: "cifuzz-campaign-run",
		Campaign: Campaign{
			MaxRunTime: "120s",
		},
		Runs:      []FuzzingRun{fuzzingRun},
		Status:    "SUCCEEDED",
		Timestamp: time.Now().Format("2006-01-02T15:04:05.999999999Z07:00"),
	}
	campaignRunBody := &CampaignRunBody{
		CampaignRun: campaignRun,
	}

	body, err := json.Marshal(campaignRunBody)
	if err != nil {
		return "", "", errors.WithStack(err)
	}

	log.Debugf("Creating campaign run: %s\n", string(body))

	resp, err := client.sendRequest("POST", fmt.Sprintf("v1/%s/campaign_runs", project), bytes.NewReader(body), token)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", responseToAPIError(resp)
	}

	return campaignRun.Name, fuzzingRun.Name, nil
}

func (client *APIClient) UploadFinding(project string, fuzzTarget string, campaignRunName string, fuzzingRunName string, finding *finding.Finding, token string) error {
	f := Finding{
		Name:        project + "/findings/cifuzz-" + finding.Name,
		DisplayName: finding.Name,
		FuzzTarget:  fuzzTarget,
		FuzzingRun:  fuzzingRunName,
		CampaignRun: campaignRunName,
		ErrorReport: ErrorReport{
			Logs:    finding.Logs,
			Details: finding.Details,
		},
		Timestamp: time.Now().Format(time.RFC3339),
	}
	findingBody := &FindingsBody{
		Findings: []Finding{f},
	}

	body, err := json.Marshal(findingBody)
	if err != nil {
		return errors.WithStack(err)
	}

	log.Debugf("Uploading finding: %s\n", string(body))

	resp, err := client.sendRequest("POST", fmt.Sprintf("v1/%s/findings", project), bytes.NewReader(body), token)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return responseToAPIError(resp)
	}

	return nil
}

func (client *APIClient) IsTokenValid(token string) (bool, error) {
	// TOOD: Change this to use another check without querying projects
	_, err := client.ListProjects(token)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			if apiErr.StatusCode == 401 {
				return false, nil
			}
		}
		return false, err
	}
	return true, nil
}

func ValidateURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return errors.WithStack(err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.Errorf("unsupported protocol scheme %q", u.Scheme)
	}
	return nil
}
