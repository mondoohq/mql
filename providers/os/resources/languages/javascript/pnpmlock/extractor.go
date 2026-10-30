// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pnpmlock

import (
	"io"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/javascript"
	"gopkg.in/yaml.v3"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*pnpmLock)(nil)
)

// Extractor parses pnpm-lock.yaml files to extract npm package dependencies.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "pnpmlock"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var lock pnpmLock
	if err := yaml.NewDecoder(r).Decode(&lock); err != nil {
		return nil, err
	}

	if filename != "" {
		lock.evidence = append(lock.evidence, filename)
	}

	return &lock, nil
}

// Root returns nil — pnpm-lock.yaml does not contain a root project entry.
func (l *pnpmLock) Root() *languages.Package {
	return nil
}

// Direct returns nil — pnpm-lock.yaml does not distinguish direct from transitive
// without cross-referencing package.json.
func (l *pnpmLock) Direct() languages.Packages {
	return nil
}

// Transitive returns all packages listed in the lockfile.
func (l *pnpmLock) Transitive() languages.Packages {
	var packages languages.Packages
	ver := l.lockfileVersionFloat()

	for key, entry := range l.Packages {
		name, version, ok := parsePnpmPackageKey(key, ver)

		// Explicit Name/Version fields take precedence (used in v9, and
		// in v5 for tarball/git packages with unparseable keys).
		if entry.Name != "" {
			name = entry.Name
			ok = true
		}
		if entry.Version != "" {
			version = entry.Version
			ok = true
		}

		if !ok || name == "" || version == "" {
			log.Warn().Str("key", key).Msg("cannot parse pnpm package key")
			continue
		}

		packages = append(packages, &languages.Package{
			Name:         name,
			Version:      version,
			Purl:         javascript.NewPackageUrl(name, version),
			Cpes:         javascript.NewCpes(name, version),
			EvidenceList: javascript.NewEvidenceList(l.evidence),
			DependsOn:    dependsOnRefs(entry.Dependencies),
			Scope:        scopeOf(entry, ver),
			Hashes:       javascript.NewHashes(entry.Resolution.Integrity),
		})
	}

	return packages
}
