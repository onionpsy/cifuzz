package login

import (
	"net/url"
	"os"

	"github.com/pkg/browser"
	"github.com/pkg/errors"

	"code-intelligence.com/cifuzz/internal/access_tokens"
	"code-intelligence.com/cifuzz/internal/api"
	"code-intelligence.com/cifuzz/pkg/dialog"
	"code-intelligence.com/cifuzz/pkg/log"
)

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

func ReadTokenInteractively(server string) (string, error) {
	url, err := url.JoinPath(server, "dashboard", "settings", "account", "tokens")
	if err != nil {
		return "", err
	}
	url += "?create&origin=cli"

	log.Printf("You need an API access token which can be generated here:\n%s", url)

	openBrowser, err := dialog.Confirm("Open browser to generate a new token?", true)
	if err != nil {
		return "", err
	}

	if openBrowser {
		err = browser.OpenURL(url)
		if err != nil {
			log.Errorf(err, "Failed to open browser: %v", err)
		}
	}

	token, err := dialog.ReadSecret("Paste your access token:", os.Stdin)
	if err != nil {
		return "", err
	}

	return token, nil
}

func CheckValidToken(apiClient *api.APIClient, token string) error {
	tokenValid, err := apiClient.IsTokenValid(token)
	if err != nil {
		return err
	}

	if !tokenValid {
		err = errors.Errorf("Invalid token: Received 401 Unauthorized from server %s", apiClient.Server)
		log.Error(err)
		return err
	}

	return nil
}

func CheckAndStoreToken(apiClient *api.APIClient, token string) error {
	err := CheckValidToken(apiClient, token)
	if err != nil {
		return err
	}
	err = access_tokens.Set(apiClient.Server, token)
	if err != nil {
		return err
	}
	log.Successf("Successfully authenticated with %s", apiClient.Server)
	log.Infof("Your API access token is stored in %s", access_tokens.GetTokenFilePath())
	return nil
}

func ReadCheckAndStoreTokenInteractively(apiClient *api.APIClient) (string, error) {
	token, err := ReadTokenInteractively(apiClient.Server)
	if err != nil {
		return "", err
	}

	err = CheckAndStoreToken(apiClient, token)
	if err != nil {
		return "", err
	}

	return token, nil
}
