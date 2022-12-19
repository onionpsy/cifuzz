package login

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pkg/browser"
	"github.com/pkg/errors"
	"golang.org/x/term"

	"code-intelligence.com/cifuzz/internal/access_tokens"
	"code-intelligence.com/cifuzz/internal/api"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/pkg/dialog"
	"code-intelligence.com/cifuzz/pkg/log"
)

type Opts struct {
	Interactive bool   `mapstructure:"interactive"`
	Server      string `mapstructure:"server"`
}

func isTokenValid(server string, token string) (bool, error) {
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

func handleNewToken(server string, token string) error {
	// Try to authenticate with the access token
	tokenValid, err := isTokenValid(server, token)
	if err != nil {
		return err
	}
	if !tokenValid {
		return errors.New("failed to authenticate with the provided API access token")
	}

	// Store the access token in the config file
	err = access_tokens.Set(server, token)
	if err != nil {
		return err
	}

	log.Successf("Successfully authenticated with %s", server)
	return nil
}

func handleExistingToken(server string, token string) error {
	tokenValid, err := isTokenValid(server, token)
	if err != nil {
		return err
	}
	if !tokenValid {
		log.Warnf(`cifuzz detected an API access token, but failed to authenticate with it.
This might happen if the token has been revoked.
Please remove the token from %s and try again.`,
			access_tokens.GetTokenFilePath())
		return cmdutils.WrapSilentError(errors.New("failed to authenticate with the provided API access token"))
	}
	log.Success("You are already logged in.")
	log.Infof("Your API access token is stored in %s", access_tokens.GetTokenFilePath())
	return nil
}

func Login(opts Opts) (string, error) {
	// Obtain the API access token
	var token string

	// First, if stdin is *not* a TTY, we try to read it from stdin,
	// in case it was provided via `cifuzz login < token-file`
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// This should never block because stdin is not a TTY.
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", errors.WithStack(err)
		}
		token = strings.TrimSpace(string(b))
	}

	// Try the environment variable
	if token == "" {
		token = os.Getenv("CIFUZZ_API_TOKEN")
	}

	// Try the access tokens config file
	if token == "" {
		token = access_tokens.Get(opts.Server)
		if token != "" {
			return token, handleExistingToken(opts.Server, token)
		}
	}

	// Try reading it interactively
	if token == "" && opts.Interactive && term.IsTerminal(int(os.Stdin.Fd())) {
		msg := fmt.Sprintf(`Enter an API access token and press Enter. You can generate a token for
your account at %s/dashboard/settings/account/tokens?create.`+"\n", opts.Server)

		err := browser.OpenURL(opts.Server + "/dashboard/settings/account/tokens?create")
		if err != nil {
			log.Error(err, "failed to open browser")
		}

		token, err = dialog.ReadSecret(msg, os.Stdin)
		if err != nil {
			return "", err
		}
	}

	if token == "" {
		err := errors.New(`No API access token provided. Please pass a valid token via stdin,
the CIFUZZ_API_TOKEN environment variable or run in interactive mode.`)
		return "", cmdutils.WrapIncorrectUsageError(err)
	}

	return token, handleNewToken(opts.Server, token)
}
