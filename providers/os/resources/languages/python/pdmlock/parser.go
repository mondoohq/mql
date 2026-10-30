// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pdmlock

// pdmLock represents a parsed pdm.lock file.
type pdmLock struct {
	Packages []pdmPackage `toml:"package"`

	// evidence is a list of file paths where the pdm.lock was found.
	evidence []string `toml:"-"`
}

// pdmPackage represents a single [[package]] entry in pdm.lock.
type pdmPackage struct {
	Name     string   `toml:"name"`
	Version  string   `toml:"version"`
	Groups   []string `toml:"groups"`
	Revision string   `toml:"revision"`
	// Dependencies is the package's own dependencies, written as PEP 508
	// requirement strings ("urllib3<3,>=1.21.1"). The constraint is a
	// REQUIREMENT; the version pdm resolved is on that package's own [[package]]
	// entry, so only the name is read from here.
	//
	// This is the package->package graph. pdm writes it into every lock and the
	// extractor did not read it, so a pdm project supplied no edges at all and
	// every transitive dependency in it stayed undetermined.
	Dependencies []string `toml:"dependencies"`
}
