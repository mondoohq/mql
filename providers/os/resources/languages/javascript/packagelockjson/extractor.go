// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packagelockjson

import (
	"encoding/json"
	"io"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/javascript"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*packageLock)(nil)
)

// Extractor is the parser for the package.lock file npm format.
// see https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json
type Extractor struct {
	// DeclaredDependencies are the production dependency names of the
	// package.json next to the lockfile. lockfileVersion 2+ records them in the
	// root `packages[""]` entry, but lockfileVersion 1 has no root entry, so
	// Direct() reads them from here for a v1 lockfile. Leave nil when there is
	// no package.json.
	DeclaredDependencies []string
}

func (p *Extractor) Name() string {
	return "packagelockjson"
}

func (p *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var packageJsonLock packageLock
	err := json.NewDecoder(r).Decode(&packageJsonLock)
	if err != nil {
		return nil, err
	}

	if filename != "" {
		packageJsonLock.evidence = append(packageJsonLock.evidence, filename)
	}
	packageJsonLock.declared = p.DeclaredDependencies

	return &packageJsonLock, nil
}

func (p *packageLock) Root() *languages.Package {
	root := &languages.Package{
		Name:         p.Name,
		Version:      p.Version,
		Purl:         javascript.NewPackageUrl(p.Name, p.Version),
		Cpes:         javascript.NewCpes(p.Name, p.Version),
		EvidenceList: javascript.NewEvidenceList(p.evidence),
	}
	return root
}

func (p *packageLock) Direct() languages.Packages {
	// search for root package, read the packages field

	if p.Packages == nil {
		return p.directV1()
	}

	rootPkg, ok := p.Packages[""]
	if !ok {
		return nil
	}

	idx := p.purlIndex()
	filteredList := []*languages.Package{}
	for name := range rootPkg.Dependencies {
		// The root's declared dependencies are keyed in `packages` by their
		// install path, node_modules/<name> (npm hoists direct deps to the root
		// node_modules), not by bare name. Look them up there; keying by bare
		// name matched nothing for lockfileVersion 2+, so Direct() returned an
		// empty set. Build Name/Purl/Cpes from the path key exactly as
		// Transitive() does, so a package's Direct and Transitive representations
		// (and their refs) are identical.
		path := "node_modules/" + name
		pkg, ok := p.Packages[path]
		if !ok {
			continue
		}

		filteredList = append(filteredList, &languages.Package{
			Name:    name,
			Version: pkg.Version,
			// npm's lockfile writes `license` as either a string or an array;
			// the parser normalizes both to a slice, and an array means a
			// choice among them.
			License:      languages.LicenseExpression(pkg.License),
			Purl:         idx[path],
			Cpes:         javascript.NewCpes(name, pkg.Version),
			EvidenceList: javascript.NewEvidenceList(p.evidence),
			DependsOn:    dependsOnRefs(p.Packages, idx, path, pkg.Dependencies),
			Scope:        scopeOf(pkg),
			Hashes:       javascript.NewHashes(pkg.Integrity),
		})
	}

	return filteredList
}

func (p *packageLock) Transitive() languages.Packages {
	var transitive languages.Packages
	if p.Packages != nil {
		idx := p.purlIndex()
		for k, v := range p.Packages {
			// Keys are install paths; the package name is the last node_modules
			// segment. The root package has key "" and carries its name in v.Name.
			name := packageLockPackageName(k)
			if k == "" {
				name = v.Name
			}

			transitive = append(transitive, &languages.Package{
				Name:    name,
				Version: v.Version,
				// Only lockfileVersion 2+ (the `packages` map) records a
				// per-package license; the legacy v1 `dependencies` tree below
				// carries none, so there is nothing to read there.
				License:      languages.LicenseExpression(v.License),
				Purl:         idx[k],
				Cpes:         javascript.NewCpes(name, v.Version),
				EvidenceList: javascript.NewEvidenceList(p.evidence),
				DependsOn:    dependsOnRefs(p.Packages, idx, k, v.Dependencies),
				Scope:        scopeOf(v),
				Hashes:       javascript.NewHashes(v.Integrity),
			})
		}
	} else if p.Dependencies != nil {
		transitive = p.appendV1(transitive, p.Dependencies, 0)
	}
	return transitive
}

// appendV1 walks a lockfileVersion 1 (or older) `dependencies` tree. A package
// that cannot be hoisted to the root, because another version already sits
// there, is nested under the package that requires it, so the tree has to be
// walked to the bottom: a top-level-only read dropped every nested version.
func (p *packageLock) appendV1(list languages.Packages, deps map[string]packageLockDependency, depth int) languages.Packages {
	if depth > maxNodeModulesDepth {
		return list
	}
	for k, v := range deps {
		list = append(list, p.v1Package(k, v))
		if len(v.Dependencies) > 0 {
			list = p.appendV1(list, v.Dependencies, depth+1)
		}
	}
	return list
}

func (p *packageLock) v1Package(name string, dep packageLockDependency) *languages.Package {
	return &languages.Package{
		Name:         name,
		Version:      dep.Version,
		Purl:         javascript.NewPackageUrl(name, dep.Version),
		Cpes:         javascript.NewCpes(name, dep.Version),
		EvidenceList: javascript.NewEvidenceList(p.evidence),
		Hashes:       javascript.NewHashes(dep.Integrity),
	}
}

// directV1 returns the direct dependencies of a lockfileVersion 1 lockfile.
// The lockfile does not say which top-level entries the project declared
// (hoisted transitive packages sit beside them), so the names come from the
// package.json; a direct dependency always resolves to the top-level entry.
func (p *packageLock) directV1() languages.Packages {
	if len(p.declared) == 0 || p.Dependencies == nil {
		return nil
	}
	var direct languages.Packages
	for _, name := range p.declared {
		dep, ok := p.Dependencies[name]
		if !ok {
			continue
		}
		direct = append(direct, p.v1Package(name, dep))
	}
	return direct
}
