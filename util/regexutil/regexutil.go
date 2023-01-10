package regexutil

import "regexp"

// FindNamedGroupsMatch finds a match using a regex with named groups and returns
// a map representing the values of the sub-matches as key-value pairs.
func FindNamedGroupsMatch(regexp *regexp.Regexp, text string) (map[string]string, bool) {
	if match := regexp.FindStringSubmatch(text); match != nil {
		result := make(map[string]string)
		for i, name := range regexp.SubexpNames() {
			if i != 0 && name != "" {
				result[name] = match[i]
			}
		}
		return result, true
	}
	return nil, false
}

// FindAllNamedGroupsMatches finds all matches using a regex with named groups and returns
// a string of maps representing the values of the sub-matches as key-value pairs.
func FindAllNamedGroupsMatches(regexp *regexp.Regexp, text string) ([]map[string]string, bool) {
	results := make([]map[string]string, 0)

	if matches := regexp.FindAllStringSubmatch(text, -1); matches != nil {
		for _, match := range matches {
			result := make(map[string]string)

			for i, name := range regexp.SubexpNames() {
				if i != 0 && name != "" {
					result[name] = match[i]
				}
			}
			results = append(results, result)
		}
	}

	if len(results) > 0 {
		return results, true
	}

	return nil, false
}
