// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pnpmlock

import (
	"fmt"
	"sort"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages"
	"go.mondoo.com/mql/providers/os/resources/languages/javascript"
)

// scopeOf maps a pnpm lock entry to a languages package scope. pnpm marks a
// dev-only package with `dev: true` in the packages map (v5/v6); v9 does not
// carry the flag per entry. So a flag-less entry means "production" only when the
// lockfile version actually distinguishes dev (v5/v6); on v9 it means "unknown",
// and we return "" rather than mislabel a dev-only package as production.
func scopeOf(entry pnpmPackageEntry, lockfileVersion float64) string {
	if entry.Dev {
		return languages.PackageScopeDev
	}
	if lockfileVersion >= 7 {
		return ""
	}
	return languages.PackageScopeProd
}

// dependsOnRefs resolves a pnpm entry's `dependencies` (name→resolved-version)
// to the refs (purls) of the depended-on packages. pnpm's store is flat and
// keyed by name+version, so each dependency value is already a concrete version;
// the ref is built the same way Transitive() builds each package's own Purl, so
// an edge ref matches its target node's Purl. Returns sorted, deduped purls.
func dependsOnRefs(deps map[string]string) []string {
	if len(deps) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var refs []string
	for name, ver := range deps {
		ver = cleanVersionSuffix(ver)
		if name == "" || ver == "" {
			continue
		}
		ref := javascript.NewPackageUrl(name, ver)
		if !seen[ref] {
			seen[ref] = true
			refs = append(refs, ref)
		}
	}
	sort.Strings(refs)
	return refs
}

// pnpmLock represents a parsed pnpm-lock.yaml file.
type pnpmLock struct {
	LockfileVersion any                         `yaml:"lockfileVersion"`
	Packages        map[string]pnpmPackageEntry `yaml:"packages"`

	// evidence is a list of file paths where the pnpm-lock.yaml was found.
	evidence []string `yaml:"-"`
}

// pnpmPackageEntry represents a single entry in the packages map.
type pnpmPackageEntry struct {
	Resolution   pnpmResolution    `yaml:"resolution"`
	Dependencies map[string]string `yaml:"dependencies"`
	Dev          bool              `yaml:"dev"`
	Name         string            `yaml:"name"`
	Version      string            `yaml:"version"`
}

// pnpmResolution describes package resolution details.
type pnpmResolution struct {
	Integrity string `yaml:"integrity"`
	Tarball   string `yaml:"tarball"`
}

// lockfileVersionFloat returns the lockfile version as a float64.
func (l *pnpmLock) lockfileVersionFloat() float64 {
	switch v := l.LockfileVersion.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case string:
		var f float64
		if _, err := fmt.Sscanf(v, "%f", &f); err == nil {
			return f
		}
	}
	return 0
}

// parsePnpmPackageKey extracts the package name and version from a pnpm
// packages map key. The format depends on the lockfile version:
//
//	v5:  /name/version or /@scope/name/version
//	v6:  /name@version or /@scope/name@version
//	v9:  name@version or @scope/name@version
func parsePnpmPackageKey(key string, version float64) (name, ver string, ok bool) {
	switch {
	case version >= 9:
		return parseAtSeparatedKey(key)
	case version >= 6:
		return parsePnpmV6Key(key)
	default:
		return parsePnpmV5Key(key)
	}
}

// parseAtSeparatedKey parses keys in the format: name@version or @scope/name@version.
// Used for both v6 (after stripping leading /) and v9 directly.
func parseAtSeparatedKey(key string) (name, ver string, ok bool) {
	// Strip parenthesized peer-dep suffixes before splitting, since they
	// can contain @ characters (e.g. "react-dom@18.2.0(react@18.2.0)").
	if idx := strings.IndexByte(key, '('); idx > 0 {
		key = key[:idx]
	}

	// For scoped packages like @scope/name@1.0.0, we need to find the
	// last @ that separates name from version (not the leading @).
	before, after, found := strings.CutLast(key, "@")
	if !found || before == "" {
		return "", "", false
	}

	name = before
	ver = cleanVersionSuffix(after)
	if name == "" || ver == "" {
		return "", "", false
	}
	return name, ver, true
}

// parsePnpmV6Key parses v6 keys: /name@version or /@scope/name@version.
func parsePnpmV6Key(key string) (name, ver string, ok bool) {
	key = strings.TrimPrefix(key, "/")
	if key == "" {
		return "", "", false
	}
	return parseAtSeparatedKey(key)
}

// parsePnpmV5Key parses v5 keys: /name/version or /@scope/name/version.
func parsePnpmV5Key(key string) (name, ver string, ok bool) {
	key = strings.TrimPrefix(key, "/")
	if key == "" {
		return "", "", false
	}

	if strings.HasPrefix(key, "@") {
		// @scope/name/version
		parts := strings.SplitN(key, "/", 3)
		if len(parts) < 3 {
			return "", "", false
		}
		name = parts[0] + "/" + parts[1]
		ver = parts[2]
	} else {
		// name/version
		parts := strings.SplitN(key, "/", 2)
		if len(parts) < 2 {
			return "", "", false
		}
		name = parts[0]
		ver = parts[1]
	}

	ver = cleanVersionSuffix(ver)
	if name == "" || ver == "" {
		return "", "", false
	}
	return name, ver, true
}

// cleanVersionSuffix strips peer dependency and parenthesized suffixes from version strings.
func cleanVersionSuffix(ver string) string {
	// Strip parenthesized suffixes first (e.g. "1.0.0(react@18.0.0)").
	if idx := strings.IndexByte(ver, '('); idx > 0 {
		ver = ver[:idx]
	}
	// Strip peer dependency suffix (e.g. "1.0.0_peer@2.0.0").
	if idx := strings.IndexByte(ver, '_'); idx > 0 {
		ver = ver[:idx]
	}
	return ver
}
