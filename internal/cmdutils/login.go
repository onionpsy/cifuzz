package cmdutils

import (
	"os"

	"code-intelligence.com/cifuzz/internal/access_tokens"
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
