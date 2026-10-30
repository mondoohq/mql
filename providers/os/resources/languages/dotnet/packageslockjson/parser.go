// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packageslockjson

// packagesLock represents a parsed packages.lock.json file.
type packagesLock struct {
	Version      int                                       `json:"version"`
	Dependencies map[string]map[string]packagesLockPackage `json:"dependencies"`

	// evidence is a list of file paths where the lock file was found.
	evidence []string `json:"-"`
}

// packagesLockPackage represents a single dependency entry.
type packagesLockPackage struct {
	Type        string `json:"type"`
	Requested   string `json:"requested"`
	Resolved    string `json:"resolved"`
	ContentHash string `json:"contentHash"`
	// Dependencies is the package's own direct dependencies, as id -> minimum
	// version. NuGet writes it for every entry it resolved, and it is the .NET
	// package->package graph: without it a consumer knows WHICH packages a
	// project restores but nothing about what reaches what, so a transitive
	// package can be neither ruled in nor ruled out.
	//
	// The version here is a MINIMUM ("8.0.0" means >= 8.0.0), not the version
	// that was resolved. The resolved one is on the sibling entry under the same
	// target framework, which is why edges are resolved by id against the
	// package set rather than read from this value.
	Dependencies map[string]string `json:"dependencies"`
}

// isDirect returns true if this is a directly referenced package.
func (p *packagesLockPackage) isDirect() bool {
	return p.Type == "Direct"
}
