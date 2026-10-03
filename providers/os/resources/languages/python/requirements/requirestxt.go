// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package requirements

import (
	"bufio"
	"io"
	"regexp"
	"strings"

	"go.mondoo.com/mql/utils/iox"
)

// firstWordRegexp is just trying to catch everything leading up the >, >=, = in a requires.txt
// Example:
//
// nose>=1.2
// Mock>=1.0
// pycryptodome
//
// [crypto]
// pycryptopp>=0.5.12
//
// [cryptography]
// cryptography
//
// would match nose / Mock / pycrptodome / etc

var firstWordRegexp = regexp.MustCompile(`^[a-zA-Z0-9\._-]*`)

// ParseRequiresTxtDependencies parses a requires.txt / requirements.txt file
// and returns a list of package names (without versions). This is the legacy
// API used internally for egg-info requires.txt files where only names matter.
func ParseRequiresTxtDependencies(r io.Reader) ([]string, error) {
	fileScanner := iox.NewLineScanner(r)
	fileScanner.Split(bufio.ScanLines)

	dependencies := []string{}
	for fileScanner.Scan() {
		line := fileScanner.Text()
		if strings.HasPrefix(line, "[") {
			// this means a new optional section of dependencies
			// so stop processing
			break
		}
		matched := firstWordRegexp.FindString(line)
		if matched == "" {
			continue
		}
		dependencies = append(dependencies, matched)
	}
	if err := fileScanner.Err(); err != nil {
		return nil, err
	}

	return dependencies, nil
}

// Requirement represents a single entry parsed from a requirements.txt file.
type Requirement struct {
	Name    string
	Version string
	Extras  []string
}

// requirementLineRegexp matches a PEP 508 dependency line:
//
//	name[extras] version_constraint ; markers # comment
var requirementLineRegexp = regexp.MustCompile(
	`^\s*` +
		`(?P<name>[a-zA-Z0-9][\w.\-]*)` +
		`(?:\[(?P<extras>[^\]]*)\])?` +
		`\s*` +
		`(?P<constraint>[~=><!][^\s;#]*(?:\s*,\s*[~=><!][^\s;#]*)*)?\s*`,
)

// ParseRequirementsTxt parses a requirements.txt file and returns structured
// requirements with names and pinned versions. It handles comments, line
// continuations, editable installs, and extras.
func ParseRequirementsTxt(r io.Reader) ([]Requirement, error) {
	scanner := bufio.NewScanner(r)
	var reqs []Requirement
	var continuation string

	for scanner.Scan() {
		line := scanner.Text()

		// Strip inline comments
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)

		// Handle line continuations
		if continuation != "" {
			line = continuation + line
			continuation = ""
		}
		if strings.HasSuffix(line, "\\") {
			continuation = strings.TrimSuffix(line, "\\")
			continue
		}

		if line == "" {
			continue
		}

		// Skip options (-r, -c, -e, --index-url, etc.)
		if strings.HasPrefix(line, "-") {
			continue
		}

		// Skip URL-only lines (e.g. "https://...")
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			continue
		}

		m := requirementLineRegexp.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[requirementLineRegexp.SubexpIndex("name")]
		extras := m[requirementLineRegexp.SubexpIndex("extras")]
		constraint := strings.TrimSpace(m[requirementLineRegexp.SubexpIndex("constraint")])

		if name == "" {
			continue
		}

		req := Requirement{Name: name}

		// Parse extras
		if extras != "" {
			for _, e := range strings.Split(extras, ",") {
				e = strings.TrimSpace(e)
				if e != "" {
					req.Extras = append(req.Extras, e)
				}
			}
		}

		// Extract pinned version from == or === operators
		req.Version = parsePinnedVersion(constraint)

		reqs = append(reqs, req)
	}

	return reqs, scanner.Err()
}

// parsePinnedVersion extracts the version from an exact pin (== or ===).
// Returns "" for unpinned or range constraints.
func parsePinnedVersion(constraint string) string {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" {
		return ""
	}

	// Reject wildcards and multi-constraint specs
	if strings.Contains(constraint, "*") || strings.Contains(constraint, ",") {
		return ""
	}

	for _, op := range []string{"===", "=="} {
		if strings.HasPrefix(constraint, op) {
			v := strings.TrimSpace(strings.TrimPrefix(constraint, op))
			if v != "" {
				return v
			}
		}
	}
	return ""
}
