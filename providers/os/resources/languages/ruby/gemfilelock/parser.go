// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gemfilelock

// gemfileLock represents a parsed Gemfile.lock file.
type gemfileLock struct {
	// Gems is the list of resolved gems from the GEM specs section.
	Gems []gemEntry
	// DirectDeps is the list of direct dependency names from the DEPENDENCIES section.
	DirectDeps map[string]bool
	// BundledWith is the Bundler version used to create this lock file.
	BundledWith string

	// evidence is a list of file paths where the Gemfile.lock was found.
	evidence []string
}

// gemEntry represents a single resolved gem in the GEM specs section.
type gemEntry struct {
	Name    string
	Version string
	// Deps are the gem names listed beneath this entry in the specs section --
	// its own runtime dependencies, as Bundler resolved them. Names only: the
	// constraint written beside each one (`rack (~> 2.2)`) is a requirement, not
	// the resolved version, which is on that gem's own spec entry.
	//
	// This is the RubyGems package->package graph. Bundler writes it into every
	// Gemfile.lock and the parser skipped past it, so a consumer could see which
	// gems a project resolves but not which of them any other gem pulls in.
	Deps []string
}
