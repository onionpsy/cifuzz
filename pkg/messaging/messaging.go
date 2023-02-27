package messaging

import (
	"math/rand"
	"net/url"
	"os"

	"code-intelligence.com/cifuzz/pkg/log"
)

func ShowServerConnectionMessage(server string) *url.Values {
	messageA := "Do you want to persist your findings?\n" + "Authenticate with the CI Fuzz Server " + server + " to get more insights."
	messageB := `Code Intelligence provides you a full history for all your findings and allows you to postpone work on findings and completely ignore them to keep the output clean and focused.

	With a free authentication you receive detailed information and solution tips for each findings in your console.
	
	All your finding data stay only with us at Code Intelligence and will never be shared
	
	Do you want to continue with authentication now?`

	additionalParams := url.Values{}
	if ComputeStablePseudoRandomNumber() == 0 {
		additionalParams.Add("utm_campaign", "A")
		log.Notef(messageA)
	} else {
		additionalParams.Add("utm_campaign", "B")
		log.Notef(messageB)
	}

	return &additionalParams
}

// To avoid that a user sees a different message each time
// we compute a stable "random" number
func ComputeStablePseudoRandomNumber() int {
	// Path name for the executable
	path, err := os.Executable()

	if err != nil {
		// As a fallback, return "true" random number
		return rand.Intn(2)
	}

	file, err := os.Stat(path)
	if err != nil {
		// As a fallback, return "true" random number
		return rand.Intn(2)
	}

	// We are using minute instead of hour
	// to avoid a "bias" for people trying
	// things out late in the evening
	minute := file.ModTime().Minute()
	if minute < 30 {
		return 0
	} else {
		return 1
	}
}
