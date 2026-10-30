// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package bunlock

import (
	"encoding/json"
	"strings"
)

// bunLock represents a parsed bun.lock file.
type bunLock struct {
	LockfileVersion int                        `json:"lockfileVersion"`
	Packages        map[string]json.RawMessage `json:"packages"`

	// evidence is a list of file paths where the bun.lock was found.
	evidence []string `json:"-"`
}

// bunPackageInfo holds extracted name and version from a bun.lock package tuple.
type bunPackageInfo struct {
	Name    string
	Version string
}

// parseBunPackageTuple extracts package info from a bun.lock tuple.
// The first element of the tuple is a string in the format:
//
//	name@version or @scope/name@version
func parseBunPackageTuple(raw json.RawMessage) (bunPackageInfo, bool) {
	var tuple []json.RawMessage
	if err := json.Unmarshal(raw, &tuple); err != nil || len(tuple) == 0 {
		return bunPackageInfo{}, false
	}

	var nameVersion string
	if err := json.Unmarshal(tuple[0], &nameVersion); err != nil {
		return bunPackageInfo{}, false
	}

	name, version := parseBunNameVersion(nameVersion)
	if name == "" || version == "" {
		return bunPackageInfo{}, false
	}

	return bunPackageInfo{Name: name, Version: version}, true
}

// parseBunNameVersion splits a "name@version" string into name and version.
// For scoped packages like "@scope/name@version", it finds the last @ that
// separates the name from the version.
func parseBunNameVersion(s string) (name, version string) {
	// Skip file: dependencies.
	if strings.HasPrefix(s, "file:") {
		return "", ""
	}

	// For scoped packages (@scope/name@version), the first @ is part of the
	// scope. Find the last @ which separates name from version.
	before, after, ok := strings.CutLast(s, "@")
	if !ok || before == "" {
		return "", ""
	}

	return before, after
}
