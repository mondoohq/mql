// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package requirements

import (
	"bufio"
	"io"
	"regexp"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages/python"
)

// ParseRequiresTxtDependencies parses an egg-info requires.txt and returns the
// names of the packages it requires in env (without versions).
//
// setuptools writes the unconditional requirements first, then one section
// per extra or marker:
//
//	requests>=2
//
//	[:python_version < "3.8"]
//	importlib-metadata
//
//	[socks]
//	PySocks
//
//	[test:sys_platform == "win32"]
//	pywin32
//
// A section with a name belongs to that extra and is optional. A section
// with only a marker ("[:...]") is required wherever its marker holds.
func ParseRequiresTxtDependencies(r io.Reader, env python.MarkerEnvironment) ([]string, error) {
	fileScanner := bufio.NewScanner(r)
	fileScanner.Split(bufio.ScanLines)

	dependencies := []string{}
	seen := map[string]bool{}
	include := true
	for fileScanner.Scan() {
		line := strings.TrimSpace(fileScanner.Text())
		if strings.HasPrefix(line, "[") {
			section := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			extra, marker, _ := strings.Cut(section, ":")
			include = strings.TrimSpace(extra) == "" && python.MarkerMayHold(marker, env)
			continue
		}
		if !include {
			continue
		}
		name, marker := python.ParseRequirement(line)
		if name == "" || !python.MarkerMayHold(marker, env) || seen[python.NormalizeName(name)] {
			continue
		}
		seen[python.NormalizeName(name)] = true
		dependencies = append(dependencies, name)
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
