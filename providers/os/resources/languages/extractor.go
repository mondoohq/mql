// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package languages

import (
	"cmp"
	"io"

	"go.mondoo.com/mql/sbom"
)

// Extractor is the common interface for all language specific bom extractors.
type Extractor interface {
	// Name of the extractor.
	Name() string
	// Parse the bom from the given reader.
	Parse(r io.Reader, filename string) (Bom, error)
}

// Bom represents a bill of materials for a specific language.
type Bom interface {
	// Root package of the bom.
	Root() *Package
	// Direct dependencies of the root package.
	Direct() Packages
	// Transitive dependencies of the root package.
	Transitive() Packages
}

// Package represents a software package.
type Package struct {
	// The name of the package.
	Name string `json:"name,omitempty"`
	// The version of the package.
	Version string `json:"version,omitempty"`
	// The architecture of the package
	Architecture string `json:"architecture,omitempty"`
	// The Common Platform Enumeration (CPE) name
	Cpes []string `json:"cpes,omitempty"`
	// The Package URL (pURL), a standardized format for defining and locating
	// software package metadata.
	Purl string `json:"purl,omitempty"`
	// location on disk
	// Deprecated: use evidence instead
	Location string `json:"location,omitempty"`
	// 'type' indicates the type of package, such as a rpm, dpkg, or gem.
	Type string `json:"type,omitempty"`
	// description of the package
	Description string `json:"description,omitempty"`
	// 'evidence_list' is a collection of evidence that supports the presence of
	// the package in the asset. This evidence could include eg. file paths
	EvidenceList []*sbom.Evidence `json:"evidence_list,omitempty"`
	// Package Origin (e.g. other package name, or source of the package)
	Origin string `json:"origin,omitempty"`
	// Package Vendor/Publisher
	Vendor string `json:"vendor,omitempty"`
	// Package Author — distinct from Vendor; some ecosystems
	// (npm/python) only carry a free-form author string.
	Author string `json:"author,omitempty"`
	// Package License — SPDX expression where the source can provide
	// one (npm package.json `license`, python METADATA `License`).
	License string `json:"license,omitempty"`
	// DependsOn holds the refs of the packages this package directly depends on
	// — the package→package edges of the dependency graph. A ref is the target
	// package's Purl (the stable, document-internal component identity, à la a
	// CycloneDX bom-ref). Populated by parsers whose lockfile resolves the
	// dependency tree (npm, Cargo, pnpm…); nil when the manifest encodes no edges
	// (e.g. Go go.mod's flat require list). Using refs (not names) disambiguates
	// the same package present at multiple versions.
	DependsOn []string `json:"depends_on,omitempty"`
	// Scope is the dependency scope: PackageScopeProd (production/runtime),
	// PackageScopeDev (development/test-only, e.g. an npm devDependency or its
	// closure), or "" when the manifest does not distinguish (e.g. Go go.mod).
	// Lets a consumer rank a CVE in a dev-only tool differently from a runtime
	// one. Populated by parsers whose lockfile carries the flag (npm today).
	Scope string `json:"scope,omitempty"`
	// Optional reports that a dependent may be built and run WITHOUT this
	// package: Maven's <optional>true</optional>, and the same idea in npm's
	// optionalDependencies and Cargo's optional features.
	//
	// It is a second axis, independent of Scope. A package can be production
	// scope and still optional — the declaring project ships it only if you ask
	// for the feature it enables.
	//
	// The distinction that makes it worth a field: an optional dependency is NOT
	// inherited by whoever depends on the declaring package. Maven and Gradle
	// both stop there, so anything walking a dependency graph has to know, and
	// a walk that does not is not slightly over-broad but wrong by a factor —
	// log4j-core alone declares 16 optional dependencies (jackson, kafka-clients,
	// jeromq, javax.mail…), none of which a project using log4j-core depends on.
	// Populated by parsers whose manifest carries the flag (Maven today).
	Optional bool `json:"optional,omitempty"`
	// Hashes are the package's integrity digests — the declared checksums a
	// lockfile records for tamper-evidence (npm's Subresource-Integrity
	// `integrity`, `dist.shasum`; …). Populated by parsers whose lockfile carries
	// them (npm today); nil otherwise. Renderers emit CycloneDX
	// `component.hashes` and SPDX package checksums.
	Hashes []PackageHash `json:"hashes,omitempty"`
}

// PackageHash is one integrity digest of a package: an algorithm label and its
// hex-encoded value. Alg uses the CycloneDX hash-algorithm spelling (e.g.
// "SHA-512", "SHA-1", "SHA-256") so renderers can map it straight through.
type PackageHash struct {
	// Alg is the hash algorithm in CycloneDX spelling (e.g. "SHA-512", "SHA-1").
	Alg string `json:"alg,omitempty"`
	// Value is the lower-case hex-encoded digest.
	Value string `json:"value,omitempty"`
}

// Dependency scopes for Package.Scope.
const (
	// PackageScopeProd is a production/runtime dependency.
	PackageScopeProd = "prod"
	// PackageScopeDev is a development/test-only dependency (not in the deployed
	// runtime).
	PackageScopeDev = "dev"
)

// SortFn is a helper function for slices.SortFunc to sort a slice of Package
// by name and version. Use it like this: slices.SortFunc(packages, sbom.SortFn)
func SortFn(a, b *Package) int {
	if n := cmp.Compare(a.Name, b.Name); n != 0 {
		return n
	}
	// if names are equal, order by version
	return cmp.Compare(a.Version, b.Version)
}

type Packages []*Package

// Find a package by name.
func (p Packages) Find(name string) *Package {
	for _, pkg := range p {
		if pkg.Name == name {
			return pkg
		}
	}
	return nil
}
