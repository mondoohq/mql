// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cargotoml

import (
	"io"

	"github.com/BurntSushi/toml"
	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/rust"
)

var (
	_ languages.Extractor = (*Extractor)(nil)
	_ languages.Bom       = (*cargoToml)(nil)
)

// Extractor parses Cargo.toml files to extract Rust project dependencies.
type Extractor struct{}

func (e *Extractor) Name() string {
	return "cargotoml"
}

func (e *Extractor) Parse(r io.Reader, filename string) (languages.Bom, error) {
	var md toml.MetaData
	var ct cargoToml
	var err error

	md, err = toml.NewDecoder(r).Decode(&ct)
	if err != nil {
		return nil, err
	}

	// Resolve dependency versions from TOML primitives.
	// Dependencies can be either strings ("1.0") or tables ({ version = "1.0" }).
	ct.resolvedDeps = resolveDeps(md, ct.Dependencies)
	ct.resolvedDevDeps = resolveDeps(md, ct.DevDependencies)
	ct.resolvedBuildDeps = resolveDeps(md, ct.BuildDependencies)

	if filename != "" {
		ct.evidence = append(ct.evidence, filename)
	}

	return &ct, nil
}

// resolveDeps extracts dependency names and versions from TOML primitives.
func resolveDeps(md toml.MetaData, deps map[string]toml.Primitive) []resolvedDep {
	var resolved []resolvedDep
	for name, prim := range deps {
		version := resolveVersion(md, prim)
		resolved = append(resolved, resolvedDep{Name: name, Version: version})
	}
	return resolved
}

// resolveVersion extracts the version string from a TOML primitive.
// Handles both string format ("1.0") and table format ({ version = "1.0" }).
func resolveVersion(md toml.MetaData, prim toml.Primitive) string {
	// Try as simple string first
	var version string
	if err := md.PrimitiveDecode(prim, &version); err == nil {
		return version
	}

	// Try as table
	var dep cargoDep
	if err := md.PrimitiveDecode(prim, &dep); err == nil {
		return dep.Version
	}

	return ""
}

// Root returns the project itself as the root package.
func (ct *cargoToml) Root() *languages.Package {
	if ct.Package.Name == "" {
		return nil
	}

	return &languages.Package{
		Name:    ct.Package.Name,
		Version: ct.Package.Version,
		// The crate's own license. Cargo's `license` is already an SPDX
		// expression, so it is carried through as written rather than
		// rebuilt from parts.
		License:      ct.Package.License,
		Purl:         rust.NewPackageUrl(ct.Package.Name, ct.Package.Version),
		Cpes:         rust.NewCpes(ct.Package.Name, ct.Package.Version),
		EvidenceList: rust.NewEvidenceList(ct.evidence),
	}
}

// Direct returns production dependencies ([dependencies] + [build-dependencies]).
func (ct *cargoToml) Direct() languages.Packages {
	var direct languages.Packages
	for _, dep := range ct.resolvedDeps {
		direct = append(direct, makePackage(dep, ct.evidence))
	}
	for _, dep := range ct.resolvedBuildDeps {
		direct = append(direct, makePackage(dep, ct.evidence))
	}
	return direct
}

// Transitive returns all declared dependencies (direct + dev + build).
// Cargo.toml only declares direct deps; true transitive resolution requires Cargo.lock.
func (ct *cargoToml) Transitive() languages.Packages {
	var all languages.Packages
	for _, dep := range ct.resolvedDeps {
		all = append(all, makePackage(dep, ct.evidence))
	}
	for _, dep := range ct.resolvedDevDeps {
		all = append(all, makePackage(dep, ct.evidence))
	}
	for _, dep := range ct.resolvedBuildDeps {
		all = append(all, makePackage(dep, ct.evidence))
	}
	return all
}

func makePackage(dep resolvedDep, evidence []string) *languages.Package {
	return &languages.Package{
		Name:         dep.Name,
		Version:      dep.Version,
		Purl:         rust.NewPackageUrl(dep.Name, dep.Version),
		Cpes:         rust.NewCpes(dep.Name, dep.Version),
		EvidenceList: rust.NewEvidenceList(evidence),
	}
}
