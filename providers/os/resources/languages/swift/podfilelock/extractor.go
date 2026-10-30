// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package podfilelock

import (
	"bufio"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/swift"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*podfileLock)(nil)
)

// Extractor parses CocoaPods Podfile.lock files.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "podfilelock"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	pl, err := parsePodfileLock(r)
	if err != nil {
		return nil, err
	}

	if filename != "" {
		pl.evidence = append(pl.evidence, filename)
	}

	return pl, nil
}

// parsePodfileLock reads a Podfile.lock and extracts pod names and versions
// from the PODS: section.
func parsePodfileLock(r io.Reader) (*podfileLock, error) {
	pl := &podfileLock{}
	scanner := bufio.NewScanner(r)
	inPods := false

	for scanner.Scan() {
		line := scanner.Text()

		// Detect section headers
		trimmed := strings.TrimSpace(line)
		if trimmed == "PODS:" {
			inPods = true
			continue
		}

		// Any other section header ends PODS
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":") && trimmed != "PODS:" {
			inPods = false
			continue
		}

		if !inPods {
			continue
		}

		// Pod entries are "  - Name (version)" (2-space indent)
		// Sub-dependencies are "    - Name (constraint)" (4+ space indent)
		// We only want top-level pods (2-space indent with "  - ")
		if !strings.HasPrefix(line, "  - ") {
			continue
		}
		// Skip sub-dependencies (indented more than 2 spaces after "  - ")
		if strings.HasPrefix(line, "    ") {
			continue
		}

		entry := parsePodEntry(strings.TrimPrefix(line, "  - "))
		if entry.Name != "" {
			pl.Pods = append(pl.Pods, entry)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return pl, nil
}

// parsePodEntry parses "Name (version)" or "Name (version):" from a PODS line.
func parsePodEntry(s string) podEntry {
	s = strings.TrimSpace(s)

	// Remove trailing colon (pods with sub-dependencies)
	s = strings.TrimSuffix(s, ":")
	s = strings.TrimSpace(s)

	// CocoaPods wraps a pod spec in double quotes when the name contains special
	// characters, e.g. `"Artsy+UIColors (3.1.0)"`. Strip the surrounding quotes so
	// the name doesn't keep a stray leading `"`.
	if len(s) >= 2 && strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		s = s[1 : len(s)-1]
	}

	// Find "(version)"
	openParen := strings.LastIndex(s, "(")
	closeParen := strings.LastIndex(s, ")")
	if openParen == -1 || closeParen == -1 || closeParen <= openParen {
		return podEntry{}
	}

	name := strings.TrimSpace(s[:openParen])
	version := s[openParen+1 : closeParen]

	return podEntry{
		Name:    name,
		Version: version,
	}
}

// Root returns nil — Podfile.lock does not describe the root project.
func (pl *podfileLock) Root() *languages.Package {
	return nil
}

// Direct returns nil — Podfile.lock does not distinguish direct from transitive in the PODS section.
func (pl *podfileLock) Direct() languages.Packages {
	return nil
}

// Transitive returns all resolved pods.
func (pl *podfileLock) Transitive() languages.Packages {
	var packages languages.Packages
	for _, pod := range pl.Pods {
		packages = append(packages, &languages.Package{
			Name:         pod.Name,
			Version:      pod.Version,
			Purl:         swift.NewCocoapodsPackageUrl(pod.Name, pod.Version),
			Cpes:         swift.NewCpes(pod.Name, pod.Version),
			EvidenceList: swift.NewEvidenceList(pl.evidence),
		})
	}
	return packages
}
