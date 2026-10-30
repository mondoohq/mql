// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cabalfreeze

import (
	"bufio"
	"io"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/haskell"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*cabalFreeze)(nil)
)

// Extractor parses Cabal cabal.project.freeze files.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "cabalfreeze"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	freeze, err := parseCabalFreeze(r)
	if err != nil {
		return nil, err
	}

	if filename != "" {
		freeze.evidence = append(freeze.evidence, filename)
	}

	return freeze, nil
}

// parseCabalFreeze reads a cabal.project.freeze file and extracts pinned versions.
// Format: "constraints: any.<name> ==<version>," lines after the "constraints:" header.
func parseCabalFreeze(r io.Reader) (*cabalFreeze, error) {
	freeze := &cabalFreeze{}
	scanner := bufio.NewScanner(r)
	inConstraints := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Detect constraints block
		if strings.HasPrefix(line, "constraints:") {
			inConstraints = true
			// The first constraint may be on the same line
			line = strings.TrimPrefix(line, "constraints:")
			line = strings.TrimSpace(line)
		}

		if !inConstraints {
			continue
		}

		// Remove trailing comma
		line = strings.TrimSuffix(line, ",")
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		// Parse "any.<name> ==<version>" format
		// Skip flag entries like "aeson +ordered-keymap" (no ==)
		if !strings.Contains(line, "==") {
			// If it doesn't look like a constraint entry at all, end the block
			if !strings.HasPrefix(line, "any.") && !strings.Contains(line, "+") && !strings.Contains(line, "-") {
				break
			}
			continue
		}

		// Split on "=="
		parts := strings.SplitN(line, "==", 2)
		if len(parts) != 2 {
			continue
		}

		nameStr := strings.TrimSpace(parts[0])
		version := strings.TrimSpace(parts[1])

		// Strip "any." prefix
		name := strings.TrimPrefix(nameStr, "any.")

		if name != "" && version != "" {
			freeze.Packages = append(freeze.Packages, cabalPackage{
				Name:    name,
				Version: version,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return freeze, nil
}

// Root returns nil — cabal.project.freeze does not describe the root project.
func (f *cabalFreeze) Root() *languages.Package {
	return nil
}

// Direct returns nil — cabal.project.freeze does not distinguish direct from transitive.
func (f *cabalFreeze) Direct() languages.Packages {
	return nil
}

// Transitive returns all pinned packages.
func (f *cabalFreeze) Transitive() languages.Packages {
	var packages languages.Packages
	for _, pkg := range f.Packages {
		packages = append(packages, &languages.Package{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Purl:         haskell.NewPackageUrl(pkg.Name, pkg.Version),
			Cpes:         haskell.NewCpes(pkg.Name, pkg.Version),
			EvidenceList: haskell.NewEvidenceList(f.evidence),
		})
	}
	return packages
}
