// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package poetrylock

import (
	"io"

	"github.com/BurntSushi/toml"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/python"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*poetryLock)(nil)
)

// Extractor parses poetry.lock files to extract Python package dependencies.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "poetrylock"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var lock poetryLock
	if _, err := toml.NewDecoder(r).Decode(&lock); err != nil {
		return nil, err
	}

	if filename != "" {
		lock.evidence = append(lock.evidence, filename)
	}

	return &lock, nil
}

// Root returns nil — poetry.lock does not contain a root project entry.
func (l *poetryLock) Root() *languages.Package {
	return nil
}

// Direct returns nil — poetry.lock does not distinguish direct from transitive.
func (l *poetryLock) Direct() languages.Packages {
	return nil
}

// Transitive returns all packages listed in the lockfile.
func (l *poetryLock) Transitive() languages.Packages {
	var packages languages.Packages
	for _, pkg := range l.Packages {
		packages = append(packages, &languages.Package{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Purl:         python.NewPackageUrl(pkg.Name, pkg.Version),
			Cpes:         python.NewCpes(pkg.Name, pkg.Version),
			EvidenceList: python.NewEvidenceList(l.evidence),
		})
	}
	return packages
}
