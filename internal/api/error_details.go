package api

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/pkg/finding"
	"code-intelligence.com/cifuzz/util/fileutil"
)

// GetErrorDetails gets the error details from the API
func (client *APIClient) GetErrorDetails(token string) ([]finding.ErrorDetails, error) {
	// FIXME: Until the endpoint is implemented, we parse the error details from the
	// local file system at ~/.local/share/error-details.json
	errorFile := filepath.Join(os.Getenv("HOME"), ".local", "share", "error-details.json")
	exists, err := fileutil.Exists(errorFile)
	if !exists || err != nil {
		return nil, errors.Wrap(err, "error details file does not exist")
	}

	file, err := os.Open(errorFile)
	if err != nil {
		return nil, errors.Wrap(err, "error opening error details file")
	}
	defer file.Close()

	var errorDetails []finding.ErrorDetails
	err = json.NewDecoder(file).Decode(&errorDetails)
	if err != nil {
		return nil, errors.Wrap(err, "error decoding error details")
	}

	return errorDetails, nil
}
