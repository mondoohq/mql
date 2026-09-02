// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cargotoml

import "github.com/BurntSushi/toml"

// cargoToml represents a parsed Cargo.toml file.
type cargoToml struct {
	Package           cargoPackageInfo          `toml:"package"`
	Dependencies      map[string]toml.Primitive `toml:"dependencies"`
	DevDependencies   map[string]toml.Primitive `toml:"dev-dependencies"`
	BuildDependencies map[string]toml.Primitive `toml:"build-dependencies"`

	// Resolved after TOML decoding (not populated by toml.Decode directly).
	resolvedDeps      []resolvedDep `toml:"-"`
	resolvedDevDeps   []resolvedDep `toml:"-"`
	resolvedBuildDeps []resolvedDep `toml:"-"`

	// evidence is a list of file paths where the Cargo.toml was found.
	evidence []string `toml:"-"`
}

// resolvedDep holds the resolved name and version of a dependency.
type resolvedDep struct {
	Name    string
	Version string
}

// cargoPackageInfo represents the [package] section.
type cargoPackageInfo struct {
	Name    string
	Version string
	Edition string
	// License is the SPDX expression Cargo asks for in `license`. Its sibling
	// `license-file` is deliberately not read: it names a file, and a path in a
	// field consumers read as a license expression is worse than an empty one.
	License string
}

// UnmarshalTOML reads [package] a field at a time so that a value Cargo allows
// but this struct cannot hold does not sink the whole manifest.
//
// The shape that forced it is workspace inheritance. A member of a Cargo
// workspace states
//
//	[package]
//	name = "member"
//	version.workspace = true
//	license.workspace = true
//
// where the inherited fields are TABLES ({workspace = true}), not strings, and
// the real values live in the workspace root manifest this extractor was not
// given. Decoding straight into string fields failed the FILE:
//
//	toml: (last key "package.version"): incompatible types: TOML value has type
//	map[string]any; destination has type string
//
// and Parse returned that error, so a workspace member reported no root, no
// dependencies and no license at all — not a missing version, an empty
// inventory. Workspace inheritance has been the standard layout since Cargo
// 1.64, and no fixture here used it.
//
// An inherited field is left empty, which is the honest answer: the value is
// stated in a file this parser does not have. Everything stated literally is
// still read.
func (p *cargoPackageInfo) UnmarshalTOML(v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	p.Name = tomlString(m["name"])
	p.Version = tomlString(m["version"])
	p.Edition = tomlString(m["edition"])
	p.License = tomlString(m["license"])
	return nil
}

// tomlString returns v when it is a string and "" for every other shape,
// including the {workspace = true} table and a missing key.
func tomlString(v any) string {
	s, _ := v.(string)
	return s
}

// cargoDep represents a dependency in table format.
type cargoDep struct {
	Version  string `toml:"version"`
	Git      string `toml:"git"`
	Path     string `toml:"path"`
	Optional bool   `toml:"optional"`
}
