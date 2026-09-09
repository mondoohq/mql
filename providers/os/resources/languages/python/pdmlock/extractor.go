// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pdmlock

import (
	"io"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/python"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*pdmLock)(nil)
)

// Extractor parses pdm.lock files to extract Python package dependencies.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "pdmlock"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var lock pdmLock
	if _, err := toml.NewDecoder(r).Decode(&lock); err != nil {
		return nil, err
	}

	if filename != "" {
		lock.evidence = append(lock.evidence, filename)
	}

	return &lock, nil
}

// Root returns nil — pdm.lock does not contain a root project entry.
func (l *pdmLock) Root() *languages.Package {
	return nil
}

// Direct returns nil — pdm.lock does not distinguish direct from transitive
// within its structure.
func (l *pdmLock) Direct() languages.Packages {
	return nil
}

// Transitive returns all packages listed in the lockfile.
func (l *pdmLock) Transitive() languages.Packages {
	byName := l.packagesByName()
	var packages languages.Packages
	for _, pkg := range l.Packages {
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

// pep508Name takes the distribution name off the front of a PEP 508 requirement
// string: `urllib3<3,>=1.21.1` is urllib3, `requests[socks]>=2.0` is requests,
// and `foo ; python_version < "3.9"` is foo.
//
// A name is letters, digits, `-`, `_` and `.` (PEP 508's identifier rule), so
// the name ends at the first character outside that set — whichever of an
// extras bracket, a version operator, a marker semicolon or whitespace comes
// first. Parsing the whole grammar is not needed to answer "which package".
func pep508Name(req string) string {
	req = strings.TrimSpace(req)
	end := 0
	for end < len(req) {
		c := req[end]
		if c == '-' || c == '_' || c == '.' ||
			c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			end++
			continue
		}
		break
	}
	return req[:end]
}

// packagesByName indexes the locked packages for edge resolution, keyed by the
// PEP 503 normalized name so a requirement spelled `charset_normalizer` finds
// the entry named `charset-normalizer`.
func (l *pdmLock) packagesByName() map[string]pdmPackage {
	out := make(map[string]pdmPackage, len(l.Packages))
	for _, p := range l.Packages {
		key := python.NormalizeName(p.Name)
		if _, dup := out[key]; !dup {
			out[key] = p
		}
	}
	return out
}

// dependsOnRefs turns one package's requirement strings into the purls of the
// packages that satisfy them.
//
// Resolved by name against the lock's own package set, never from the version
// in the requirement: that is a constraint, so a purl built from it would name
// a package pdm did not resolve and the edge would point at nothing. A name
// with no entry is dropped rather than synthesised — pdm writes one entry per
// resolved package, so a name it does not have is one this lock did not
// resolve (a dependency of an unselected group, most often).
func (l *pdmLock) dependsOnRefs(pkg pdmPackage, byName map[string]pdmPackage) []string {
	if len(pkg.Dependencies) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var refs []string
	for _, req := range pkg.Dependencies {
		name := pep508Name(req)
		if name == "" {
			continue
		}
		target, ok := byName[python.NormalizeName(name)]
		if !ok || target.Version == "" {
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
