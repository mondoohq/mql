// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pipfilelock

import (
	"encoding/json"
	"io"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/python"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*pipfileLock)(nil)
)

// Extractor parses Pipfile.lock files to extract Python package dependencies.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "pipfilelock"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var lock pipfileLock
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, err
	}

	if filename != "" {
		lock.evidence = append(lock.evidence, filename)
	}

	return &lock, nil
}

// Root returns nil — Pipfile.lock does not contain a root project entry.
func (l *pipfileLock) Root() *languages.Package {
	return nil
}

// Direct returns packages from the "default" section (production dependencies).
func (l *pipfileLock) Direct() languages.Packages {
	return l.packagesFrom(l.Default)
}

// Transitive returns all packages from both "default" and "develop" sections.
// Note: this is a superset of Direct() — it includes all resolved dependencies
// regardless of group, matching the convention used by other extractors where
// Transitive() returns all non-root packages.
func (l *pipfileLock) Transitive() languages.Packages {
	packages := l.packagesFrom(l.Default)

	seen := make(map[string]bool, len(packages))
	for _, p := range packages {
		seen[p.Name] = true
	}

	// Add develop packages, skipping duplicates.
	for name, pkg := range l.Develop {
		if seen[name] {
			continue
		}
		version := cleanVersion(pkg.Version)
		packages = append(packages, &languages.Package{
			Name:         name,
			Version:      version,
			Purl:         python.NewPackageUrl(name, version),
			Cpes:         python.NewCpes(name, version),
			EvidenceList: python.NewEvidenceList(l.evidence),
		})
	}

	return packages
}

func (l *pipfileLock) packagesFrom(deps map[string]pipfilePackage) languages.Packages {
	var packages languages.Packages
	for name, pkg := range deps {
		version := cleanVersion(pkg.Version)
		packages = append(packages, &languages.Package{
			Name:         name,
			Version:      version,
			Purl:         python.NewPackageUrl(name, version),
			Cpes:         python.NewCpes(name, version),
			EvidenceList: python.NewEvidenceList(l.evidence),
		})
	}
	return packages
}
