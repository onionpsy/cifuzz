package api

import (
	"encoding/json"
	"io"
	"net/url"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/pkg/finding"
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
		return nil, responseToAPIError(resp)
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
