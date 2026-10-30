// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gosum

import (
	"bufio"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/golang"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*goSum)(nil)
)

// Extractor parses go.sum files to extract Go module dependencies with their hashes.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "gosum"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	sum, err := parseGoSum(r)
	if err != nil {
		return nil, err
	}

	if filename != "" {
		sum.evidence = append(sum.evidence, filename)
	}

	return sum, nil
}

// parseGoSum parses a go.sum file from a reader.
func parseGoSum(r io.Reader) (*goSum, error) {
	sum := &goSum{}
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 3 {
			continue
		}

		modulePath := parts[0]
		version := parts[1]
		hash := parts[2]

		// Skip /go.mod hash entries — we only want the module source hash.
		if strings.HasSuffix(version, "/go.mod") {
			continue
		}

		// Deduplicate entries (same module@version can appear if go.sum is not clean).
		key := modulePath + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true

		sum.Entries = append(sum.Entries, goSumEntry{
			Path:    modulePath,
			Version: version,
			Hash:    hash,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return sum, nil
}

// Root returns nil for go.sum since it does not contain root module information.
func (s *goSum) Root() *languages.Package {
	return nil
}

// Direct returns nil for go.sum since it cannot distinguish direct from indirect.
func (s *goSum) Direct() languages.Packages {
	return nil
}

// Transitive returns all modules listed in go.sum.
func (s *goSum) Transitive() languages.Packages {
	var packages languages.Packages
	for _, entry := range s.Entries {
		packages = append(packages, &languages.Package{
			Name:         entry.Path,
			Version:      entry.Version,
			Purl:         golang.NewPackageUrl(entry.Path, entry.Version),
			Cpes:         golang.NewCpes(entry.Path, entry.Version),
			EvidenceList: golang.NewEvidenceList(s.evidence),
		})
	}
	return packages
}
