// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pubspeclock

import (
	"io"

	"gopkg.in/yaml.v3"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/dart"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*pubspecLock)(nil)
)

// Extractor parses Dart/Flutter pubspec.lock files.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "pubspeclock"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var lock pubspecLock

	if filename != "" {
		lock.evidence = append(lock.evidence, filename)
	}

	if err := yaml.NewDecoder(r).Decode(&lock); err != nil {
		return nil, err
	}

	return &lock, nil
}

// Root returns nil — pubspec.lock does not describe the root project.
func (l *pubspecLock) Root() *languages.Package {
	return nil
}

// Direct returns direct production dependencies (dependency: "direct main").
func (l *pubspecLock) Direct() languages.Packages {
	var direct languages.Packages
	for name, pkg := range l.Packages {
		if !pkg.isDirectMain() {
			continue
		}
		direct = append(direct, makePackage(name, pkg, l.evidence))
	}
	return direct
}

// Transitive returns all packages (direct main + direct dev + transitive).
func (l *pubspecLock) Transitive() languages.Packages {
	var all languages.Packages
	for name, pkg := range l.Packages {
		all = append(all, makePackage(name, pkg, l.evidence))
	}
	return all
}

func makePackage(name string, pkg pubspecPackage, evidence []string) *languages.Package {
	return &languages.Package{
		Name:         name,
		Version:      pkg.Version,
		Purl:         dart.NewPackageUrl(name, pkg.Version),
		Cpes:         dart.NewCpes(name, pkg.Version),
		EvidenceList: dart.NewEvidenceList(evidence),
	}
}
