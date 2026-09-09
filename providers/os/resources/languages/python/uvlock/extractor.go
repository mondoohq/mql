// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package uvlock

import (
	"io"
	"sort"

	"github.com/BurntSushi/toml"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/python"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*uvLock)(nil)
)

// Extractor parses uv.lock files to extract Python package dependencies.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "uvlock"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var lock uvLock
	if _, err := toml.NewDecoder(r).Decode(&lock); err != nil {
		return nil, err
	}

	if filename != "" {
		lock.evidence = append(lock.evidence, filename)
	}

	return &lock, nil
}

// Root returns the root project package (the entry with virtual source ".").
func (l *uvLock) Root() *languages.Package {
	for _, pkg := range l.Packages {
		if pkg.isRoot() {
			return &languages.Package{
				Name:         pkg.Name,
				Version:      pkg.Version,
				Purl:         python.NewPackageUrl(pkg.Name, pkg.Version),
				Cpes:         python.NewCpes(pkg.Name, pkg.Version),
				EvidenceList: python.NewEvidenceList(l.evidence),
			}
		}
	}
	return nil
}

// Direct returns nil — uv.lock does not distinguish direct from transitive.
func (l *uvLock) Direct() languages.Packages {
	return nil
}

// Transitive returns all packages (excluding the root project).
func (l *uvLock) Transitive() languages.Packages {
	byName := l.packagesByName()
	var packages languages.Packages
	for _, pkg := range l.Packages {
		if pkg.isRoot() {
			continue
		}
		packages = append(packages, &languages.Package{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Purl:         python.NewPackageUrl(pkg.Name, pkg.Version),
			Cpes:         python.NewCpes(pkg.Name, pkg.Version),
			EvidenceList: python.NewEvidenceList(l.evidence),
			DependsOn:    l.dependsOnRefs(pkg, byName),
		})
	}
	return packages
}

// packagesByName indexes the locked packages for edge resolution, keyed by the
// PEP 503 normalized name so a dependency spelled `charset_normalizer` finds
// the entry named `charset-normalizer`.
func (l *uvLock) packagesByName() map[string]uvPackage {
	out := make(map[string]uvPackage, len(l.Packages))
	for _, p := range l.Packages {
		key := python.NormalizeName(p.Name)
		if _, dup := out[key]; !dup {
			out[key] = p
		}
	}
	return out
}

// dependsOnRefs turns one package's dependency names into the purls of the
// packages that satisfy them.
//
// Resolved by name against the lock's own package set, so an edge's target is
// always a package the inventory contains — which is what the reachability
// classifier requires before it will draw a negative verdict from the graph's
// shape. A name with no entry is dropped rather than synthesised: uv writes one
// entry per resolved package, so a name it does not have is one this lock did
// not resolve.
func (l *uvLock) dependsOnRefs(pkg uvPackage, byName map[string]uvPackage) []string {
	names := make([]uvDependency, 0, len(pkg.Dependencies))
	names = append(names, pkg.Dependencies...)
	for _, extra := range pkg.OptionalDependencies {
		names = append(names, extra...)
	}
	if len(names) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var refs []string
	for _, dep := range names {
		target, ok := byName[python.NormalizeName(dep.Name)]
		if !ok || target.Version == "" || target.isRoot() {
			continue
		}
		ref := python.NewPackageUrl(target.Name, target.Version)
		if seen[ref] {
			continue
		}
		seen[ref] = true
		refs = append(refs, ref)
	}
	if len(refs) == 0 {
		return nil
	}
	sort.Strings(refs)
	return refs
}
