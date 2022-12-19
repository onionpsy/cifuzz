package cmdutils

import (
	"os"

	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/internal/access_tokens"
	"code-intelligence.com/cifuzz/internal/api"
	"code-intelligence.com/cifuzz/pkg/log"
)

func IsTokenValid(server string, token string) (bool, error) {
	client := api.APIClient{Server: server}
	// TOOD: Change this to use another check without querying projects
	_, err := client.ListProjects(token)
	if err != nil {
		var apiErr *api.APIError
		if errors.As(err, &apiErr) {
			if apiErr.StatusCode == 401 {
				return false, nil
			}
		}
		return false, err
	}
	return true, nil
}

func GetToken(server string) string {
	// Try the environment variable
	token := os.Getenv("CIFUZZ_API_TOKEN")
	if token != "" {
		log.Print("Using token from $CIFUZZ_API_TOKEN")
		return token
	}

	// Try the access tokens config file
	return access_tokens.Get(server)
}
