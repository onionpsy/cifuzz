package api

import (
	"encoding/json"
	"io"
	"net/url"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/pkg/finding"
	"code-intelligence.com/cifuzz/pkg/log"
)

// GetErrorDetails gets the error details from the API
func (client *APIClient) GetErrorDetails(token string) ([]finding.ErrorDetails, error) {
	// get it from the API
	url, err := url.JoinPath("v2", "error-details")
	if err != nil {
		return nil, err
	}

	resp, err := client.sendRequest("GET", url, nil, token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		// the request did not succeed, but we don't want the entire process to fail
		// so we just log the error and return an empty list
		log.Warnf("Error getting error details: %s", resp.Status)
		log.Info("Continuing without external error details")
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var errorDetails []finding.ErrorDetails
	err = json.Unmarshal(body, &errorDetails)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return errorDetails, nil
}
