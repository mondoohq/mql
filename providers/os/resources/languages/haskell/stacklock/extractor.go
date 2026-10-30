// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package stacklock

import (
	"io"

	"gopkg.in/yaml.v3"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/haskell"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*stackLock)(nil)
)

// Extractor parses Stack stack.yaml.lock files.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "stacklock"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var lock stackLock

	if filename != "" {
		lock.evidence = append(lock.evidence, filename)
	}

	if err := yaml.NewDecoder(r).Decode(&lock); err != nil {
		return nil, err
	}

	return &lock, nil
}

// Root returns nil — stack.yaml.lock does not describe the root project.
func (l *stackLock) Root() *languages.Package {
	return nil
}

// Direct returns nil — stack.yaml.lock does not distinguish direct from transitive.
func (l *stackLock) Direct() languages.Packages {
	return nil
}

// Transitive returns all resolved packages.
func (l *stackLock) Transitive() languages.Packages {
	var packages languages.Packages
	for _, pkg := range l.Packages {
		ref := pkg.Completed.Hackage
		if ref == "" {
			continue
		}

		name, version := haskell.ParseHackageRef(ref)
		if name == "" {
			continue
		}

		packages = append(packages, &languages.Package{
			Name:         name,
			Version:      version,
			Purl:         haskell.NewPackageUrl(name, version),
			Cpes:         haskell.NewCpes(name, version),
			EvidenceList: haskell.NewEvidenceList(l.evidence),
		})
	}
	return packages
}
