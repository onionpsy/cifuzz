package api

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/pkg/log"
)

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

// CreateCampaignRun creates a new campaign run for the given project and
// returns the name of the campaign and fuzzing run. The campaign and fuzzing
// run name is used to identify the campaign run in the API for consecutive
// calls.
func (client *APIClient) CreateCampaignRun(project string, token string, fuzzTarget string, numBuildJobs uint) (string, string, error) {
	fuzzTarget = base64.URLEncoding.EncodeToString([]byte(fuzzTarget))

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
