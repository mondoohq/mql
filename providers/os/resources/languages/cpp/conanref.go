// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cpp

import "strings"

// ParseConanRef parses a Conan reference string in the format:
//
//	name/version[@[user/channel]][#revision][%timestamp]
//
// Every component is returned; the caller decides which ones its purl carries.
// `name/version@` with an empty user/channel is legal Conan and means the
// ConanCenter-style no-user form, so it parses to empty User and Channel rather
// than failing.
//
// Shared by both Conan sources — the lockfile and the conanfile — because they
// spell a reference the same way and a second parser would drift from this one.
func ParseConanRef(ref string) (ConanCoordinate, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ConanCoordinate{}, false
	}

	// A v2 lockfile appends the recipe timestamp after the revision. Drop it
	// first: it is lockfile bookkeeping, not part of the reference.
	if idx := strings.IndexByte(ref, '%'); idx >= 0 {
		ref = ref[:idx]
	}

	// Recipe revision.
	var revision string
	if idx := strings.IndexByte(ref, '#'); idx >= 0 {
		revision = ref[idx+1:]
		ref = ref[:idx]
	}

	// User and channel.
	var user, channel string
	if idx := strings.IndexByte(ref, '@'); idx >= 0 {
		user, channel, _ = strings.Cut(ref[idx+1:], "/")
		ref = ref[:idx]
	}

	name, version, ok := strings.Cut(ref, "/")
	if !ok || name == "" || version == "" {
		return ConanCoordinate{}, false
	}

	return ConanCoordinate{
		Name:     name,
		Version:  version,
		User:     user,
		Channel:  channel,
		Revision: revision,
	}, true
}

// ResolvedVersion returns the coordinate's version when it is an exact one, and
// "" when it is a version RANGE.
//
// Conan writes a range in brackets — "fmt/[>=9.0]", "zlib/[*]", "boost/[>1 <2]"
// — and a range is not a version: it states what would be acceptable, not what
// is installed. Reporting "[>=9.0]" as a version produces a coordinate that
// matches no advisory and reads in a report as though it were one. An empty
// version says the manifest did not resolve it, which is the truth; conan.lock
// is the file that does.
func (c ConanCoordinate) ResolvedVersion() string {
	if strings.ContainsAny(c.Version, "[]") {
		return ""
	}
	return c.Version
}
