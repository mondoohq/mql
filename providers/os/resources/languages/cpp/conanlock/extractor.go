// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package conanlock

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/cpp"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*conanLock)(nil)
)

// Extractor parses conan.lock files to extract C/C++ package dependencies.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "conanlock"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var lock conanLock
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, err
	}

	if filename != "" {
		lock.evidence = append(lock.evidence, filename)
	}

	return &lock, nil
}

// Root returns nil — conan.lock records a resolved graph, not the consumer's
// own identity. The v1 consumer node carries a path to the conanfile and no
// reference of its own, so there is no name or version to report.
func (l *conanLock) Root() *languages.Package {
	return nil
}

// Direct returns the packages the project itself requires.
//
// A v2 lockfile's `requires` list IS the direct set — Conan writes the
// consumer's own requirements there and resolves their closure into the same
// list, so this is a superset of the true direct set rather than an exact one.
// It is still the better answer: reporting everything as transitive (which is
// what returning nil did) classified every Conan package as unreachable-by-
// default, so `deps list --scope direct` returned nothing at all and the
// direct-unused demotion could never fire.
//
// A v1 graph lock encodes real edges but this parser does not yet walk them, so
// v1 reports its packages as transitive and Direct is empty. That is the honest
// answer for v1 rather than a guess dressed as the same thing.
func (l *conanLock) Direct() languages.Packages {
	if !l.isV2() {
		return nil
	}
	return l.parseV2()
}

// Transitive returns the packages not already reported as direct. Direct and
// Transitive must not overlap: a package listed by both is emitted twice.
func (l *conanLock) Transitive() languages.Packages {
	if l.isV2() {
		return nil
	}
	return l.parseV1()
}

// parseV1 extracts packages from the v1 graph_lock format.
func (l *conanLock) parseV1() languages.Packages {
	var packages languages.Packages

	// Deterministic order: a lockfile's nodes are a JSON object, and ranging a
	// map would reorder the SBOM between runs of the same scan.
	ids := make([]string, 0, len(l.GraphLock.Nodes))
	for id := range l.GraphLock.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		node := l.GraphLock.Nodes[id]
		// Skip local path dependencies.
		if node.Path != "" {
			continue
		}

		// Use pref (v0.3) or ref (v0.4+).
		ref := node.Ref
		if node.Pref != "" {
			ref = node.Pref
		}

		parsed, ok := cpp.ParseConanRef(ref)
		if !ok {
			log.Warn().Str("ref", ref).Msg("cannot parse conan reference")
			continue
		}

		// A v1 lockfile marks build tooling with the node's context rather than
		// with a separate list, so the two formats agree on scope instead of v1
		// reporting none at all.
		scope := languages.PackageScopeProd
		if node.Context == "build" {
			scope = languages.PackageScopeDev
		}

		packages = append(packages, newConanPackage(parsed, scope, l.evidence))
	}

	return packages
}

// parseV2 extracts packages from the v2 requires/build_requires format.
func (l *conanLock) parseV2() languages.Packages {
	var packages languages.Packages

	add := func(refs []string, scope string) {
		for _, ref := range refs {
			parsed, ok := cpp.ParseConanRef(ref)
			if !ok {
				log.Warn().Str("ref", ref).Msg("cannot parse conan reference")
				continue
			}
			packages = append(packages, newConanPackage(parsed, scope, l.evidence))
		}
	}

	// `requires` are runtime/production dependencies; `build_requires`,
	// `python_requires` and `config_requires` are build-time tooling (compilers,
	// cmake, conan extensions and config packages) that isn't in the produced
	// artifact — reported as dev scope so consumers can drop them from a
	// production view.
	add(l.Requires, languages.PackageScopeProd)
	add(l.BuildRequires, languages.PackageScopeDev)
	add(l.PythonRequires, languages.PackageScopeDev)
	add(l.ConfigRequires, languages.PackageScopeDev)

	return packages
}

// newConanPackage builds a package from a parsed reference, carrying the whole
// coordinate into the purl.
func newConanPackage(ref cpp.ConanCoordinate, scope string, evidence []string) *languages.Package {
	return &languages.Package{
		Name:         ref.Name,
		Version:      ref.ResolvedVersion(),
		Purl:         cpp.NewConanPackageUrl(ref),
		EvidenceList: cpp.NewEvidenceList(evidence),
		Scope:        scope,
	}
}
