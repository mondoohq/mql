// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package wheelegg

import (
	"strings"
)

// ParseDistInfoName derives a package name and version from the name of a
// ".dist-info" or ".egg-info" entry, e.g. "requests-2.32.3.dist-info" ->
// ("requests", "2.32.3").
//
// This is a fallback for installs whose METADATA / PKG-INFO is missing or
// unparsable. That is common enough to matter: a package removed in a later
// container image layer leaves the directory in the merged listing without its
// metadata, and interrupted installs leave the same shape behind. The directory
// name still carries the identity, so the package can be reported instead of
// silently dropped from the inventory.
//
// The version is only returned when it looks like one (leading digit). Names
// without a version part, such as a bare "foo.egg-info", yield an empty version.
func ParseDistInfoName(entry string) (name string, version string) {
	trimmed := strings.TrimSuffix(strings.TrimSuffix(entry, ".dist-info"), ".egg-info")
	if trimmed == "" {
		return "", ""
	}

	parts := strings.Split(trimmed, "-")

	// egg-info directories may carry build tags after the version, such as
	// "foo-1.2.3-py3.11.egg-info". Drop them so the version stays the last part.
	for len(parts) > 1 {
		last := parts[len(parts)-1]
		if strings.HasPrefix(last, "py") || strings.HasPrefix(last, "cp") {
			parts = parts[:len(parts)-1]
			continue
		}
		break
	}

	if len(parts) < 2 {
		return trimmed, ""
	}

	last := parts[len(parts)-1]
	if last == "" || last[0] < '0' || last[0] > '9' {
		// not a version; the hyphen belongs to the name
		return trimmed, ""
	}

	return strings.Join(parts[:len(parts)-1], "-"), last
}
