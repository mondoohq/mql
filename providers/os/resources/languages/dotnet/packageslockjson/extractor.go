// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packageslockjson

import (
	"encoding/json"
	"io"
	"sort"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/dotnet"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*packagesLock)(nil)
)

// Extractor parses NuGet packages.lock.json files.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "packageslockjson"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var lock packagesLock
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, err
	}

	if filename != "" {
		lock.evidence = append(lock.evidence, filename)
	}

	return &lock, nil
}

// allPackages returns a deduplicated list of packages across all target frameworks.
//
// Target frameworks are visited in sorted order so "first occurrence wins" is a
// rule rather than a coin toss. They usually agree on versions, but a project
// that multi-targets can resolve a package differently per framework, and
// ranging the map directly made WHICH version got inventoried depend on Go's
// map iteration order -- a different SBOM from the same file on the same commit.
func (l *packagesLock) allPackages() map[string]packagesLockPackage {
	seen := make(map[string]packagesLockPackage)
	for _, tfm := range l.frameworks() {
		for name, pkg := range l.Dependencies[tfm] {
			// First occurrence wins (frameworks typically have the same versions)
			if _, ok := seen[name]; !ok {
				seen[name] = pkg
			}
		}
	}
	return seen
}

// frameworks returns the target framework monikers in sorted order.
func (l *packagesLock) frameworks() []string {
	out := make([]string, 0, len(l.Dependencies))
	for tfm := range l.Dependencies {
		out = append(out, tfm)
	}
	sort.Strings(out)
	return out
}

// dependsOnRefs turns one entry's `dependencies` map into purls of the packages
// that satisfy it.
//
// Resolution is by id against the SAME package set this file emits, never from
// the version written beside the id: that version is a minimum constraint, so
// building a purl from it would name a package that is not in the inventory and
// produce an edge pointing at nothing. Looking the id up in `all` also keeps the
// graph self-consistent with the packages -- an edge's target is a node that
// exists -- which is what the reachability classifier requires before it will
// draw a negative verdict from the graph's shape.
//
// An id with no entry is dropped rather than synthesised. It means the lockfile
// named a dependency it did not resolve, and inventing the node would assert a
// package the project does not restore.
func dependsOnRefs(deps map[string]string, all map[string]packagesLockPackage) []string {
	if len(deps) == 0 {
		return nil
	}
	var refs []string
	for name := range deps {
		target, ok := all[name]
		if !ok || target.Resolved == "" {
			continue
		}
		refs = append(refs, dotnet.NewPackageUrl(name, target.Resolved))
	}
	if len(refs) == 0 {
		return nil
	}
	sort.Strings(refs)
	return refs
}

// Root returns nil — packages.lock.json does not contain root project info.
func (l *packagesLock) Root() *languages.Package {
	return nil
}

// Direct returns packages with type "Direct".
func (l *packagesLock) Direct() languages.Packages {
	all := l.allPackages()
	var direct languages.Packages
	for name, pkg := range all {
		if pkg.isDirect() {
			direct = append(direct, makePackage(name, pkg, all, l.evidence))
		}
	}
	return direct
}

// Transitive returns all packages (both direct and transitive).
func (l *packagesLock) Transitive() languages.Packages {
	all := l.allPackages()
	var out languages.Packages
	for name, pkg := range all {
		out = append(out, makePackage(name, pkg, all, l.evidence))
	}
	return out
}

func makePackage(name string, pkg packagesLockPackage, all map[string]packagesLockPackage, evidence []string) *languages.Package {
	version := pkg.Resolved
	return &languages.Package{
		Name:         name,
		Version:      version,
		Purl:         dotnet.NewPackageUrl(name, version),
		Cpes:         dotnet.NewCpes(name, version),
		EvidenceList: dotnet.NewEvidenceList(evidence),
		DependsOn:    dependsOnRefs(pkg.Dependencies, all),
	}
}
