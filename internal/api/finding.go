package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/pkg/finding"
	"code-intelligence.com/cifuzz/pkg/log"
)

type Findings struct {
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
	findingBody := &Findings{
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
