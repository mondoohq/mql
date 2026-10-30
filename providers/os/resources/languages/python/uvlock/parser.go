// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package uvlock

// uvLock represents a parsed uv.lock file.
type uvLock struct {
	Version  int         `toml:"version"`
	Packages []uvPackage `toml:"package"`

	// evidence is a list of file paths where the uv.lock was found.
	evidence []string `toml:"-"`
}

// uvPackage represents a single [[package]] entry in uv.lock.
type uvPackage struct {
	Name    string   `toml:"name"`
	Version string   `toml:"version"`
	Source  uvSource `toml:"source"`
	// Dependencies is the package's own resolved runtime dependencies. uv
	// writes them as a table per entry (`{ name = "certifi" }`), naming only
	// the package -- the version it resolved to is on that package's own
	// [[package]] entry, which is where dependsOnRefs looks it up.
	//
	// This is the package->package graph. uv writes it into every lock and the
	// extractor did not read it, so a uv project supplied no edges at all and
	// every transitive dependency in it stayed undetermined.
	Dependencies []uvDependency `toml:"dependencies"`
	// OptionalDependencies are the extras: `pip install foo[socks]` pulls them
	// in, a plain install does not.
	//
	// They ARE folded into the graph, deliberately. uv locks an optional
	// dependency only because some configuration of this project needs it, and
	// the flat DependsOn list has no channel for "reached only under an extra".
	// Omitting the edge would leave such a package reached by nothing and
	// eligible to be called an orphan -- a demotion, on a package an install
	// with that extra really does ship. Including it errs toward keeping.
	OptionalDependencies map[string][]uvDependency `toml:"optional-dependencies"`
}

// uvDependency is one entry in a package's dependency table. Only the name is
// read: uv states the resolved version once, on the package's own entry.
type uvDependency struct {
	Name string `toml:"name"`
}

// uvSource describes where a package was sourced from.
type uvSource struct {
	Virtual  string `toml:"virtual"`
	Registry string `toml:"registry"`
	Git      string `toml:"git"`
}

// isRoot returns true if this package is the root project (virtual source).
func (p *uvPackage) isRoot() bool {
	return p.Source.Virtual == "."
}
