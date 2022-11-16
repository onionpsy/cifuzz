package coverage

import "code-intelligence.com/cifuzz/internal/config"

var ValidOutputFormats = map[string][]string{
	config.BuildSystemCMake:  {"html", "lcov"},
	config.BuildSystemBazel:  {"html", "lcov"},
	config.BuildSystemOther:  {"html", "lcov"},
	config.BuildSystemMaven:  {"html"},
	config.BuildSystemGradle: {"html"},
}
