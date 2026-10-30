// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cargolock

import (
	"sort"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages/rust"
)

// dependsOnRefs resolves a Cargo package's `dependencies` to the refs (purls) of
// the depended-on crates. A Cargo.lock dependency string is "name", "name
// version", or "name version (source)"; when no version is given it is
// unambiguous only if a single version of that crate is locked. The ref is built
// the same way Transitive() builds each crate's own Purl, so an edge ref matches
// its target node's Purl. Cargo.lock does not distinguish dev from normal
// dependencies (the resolve graph is unified), so no scope is derived.
func dependsOnRefs(byName map[string][]string, deps []string) []string {
	if len(deps) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var refs []string
	for _, dep := range deps {
		name, version := parseCargoDependency(dep)
		if version == "" {
			// No version pinned in the edge: resolvable only if exactly one
			// version of this crate is locked.
			if versions := byName[name]; len(versions) == 1 {
				version = versions[0]
			} else {
				continue
			}
		}
		ref := rust.NewPackageUrl(name, version)
		if !seen[ref] {
			seen[ref] = true
			refs = append(refs, ref)
		}
	}
	sort.Strings(refs)
	return refs
}

// parseCargoDependency splits a Cargo.lock dependency string into name and
// version. Forms: "name", "name version", "name version (source)".
func parseCargoDependency(dep string) (name, version string) {
	fields := strings.Fields(dep)
	switch {
	case len(fields) == 0:
		return "", ""
	case len(fields) == 1:
		return fields[0], ""
	default:
		return fields[0], fields[1]
	}
}

// cargoLock represents a parsed Cargo.lock file.
type cargoLock struct {
	Version  int            `toml:"version"`
	Packages []cargoPackage `toml:"package"`

	// evidence is a list of file paths where the Cargo.lock was found.
	evidence []string `toml:"-"`
}

// cargoPackage represents a single [[package]] entry in Cargo.lock.
type cargoPackage struct {
	Name         string   `toml:"name"`
	Version      string   `toml:"version"`
	Source       string   `toml:"source"`
	Checksum     string   `toml:"checksum"`
	Dependencies []string `toml:"dependencies"`
}

// isRoot returns true if this package is the root project (no source field).
func (p *cargoPackage) isRoot() bool {
	return p.Source == ""
}
