// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gemspec

// gemSpec represents a parsed .gemspec file.
type gemSpec struct {
	// Name is the gem name.
	Name string
	// Version is the gem version (may be empty if it references a constant).
	Version string
	// Licenses holds the licenses the gemspec declares, in the order it wrote
	// them. A gemspec states them with either `spec.license = "MIT"` or
	// `spec.licenses = ["MIT", "Apache-2.0"]`; RubyGems keeps a single list
	// either way, so this does too.
	Licenses []string
	// Dependencies is the list of declared dependencies.
	Dependencies []gemDep

	// evidence is a list of file paths where the gemspec was found.
	evidence []string
}

// gemDep represents a declared dependency in a gemspec.
type gemDep struct {
	Name       string
	Constraint string
	IsDev      bool
}
