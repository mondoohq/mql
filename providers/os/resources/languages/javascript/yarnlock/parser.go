// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package yarnlock

import (
	"errors"
	"regexp"
	"sort"
	"strings"

	"go.mondoo.com/mql/providers/os/resources/languages/javascript"
)

// specIndex maps each "name@versionSpec" a yarn.lock entry answers to the
// resolved version of that entry. A single entry key can list several comma-
// separated specs (e.g. "has@^1.0.1, has@^1.0.3"), all resolving to one version.
func (l yarnLock) specIndex() map[string]string {
	idx := map[string]string{}
	for key, entry := range l {
		for _, spec := range strings.Split(key, ",") {
			spec = strings.TrimSpace(spec)
			if spec != "" {
				idx[spec] = entry.Version
			}
		}
	}
	return idx
}

// dependsOnRefs resolves an entry's `dependencies` (name→versionSpec) to the
// refs (purls) of the depended-on packages, using specIndex to map each required
// spec to the concrete resolved version. The ref is built the same way
// Transitive() builds each package's own Purl, so an edge ref matches its target
// node's Purl. yarn.lock (v1) does not distinguish dev from prod, so no scope is
// derived. Returns sorted, deduped purls.
func dependsOnRefs(idx map[string]string, deps map[string]string) []string {
	if len(deps) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var refs []string
	for name, spec := range deps {
		version, ok := idx[name+"@"+spec]
		if !ok || version == "" {
			continue
		}
		ref := javascript.NewPackageUrl(name, version)
		if !seen[ref] {
			seen[ref] = true
			refs = append(refs, ref)
		}
	}
	sort.Strings(refs)
	return refs
}

type yarnLock map[string]yarnLockEntry

type yarnLockEntry struct {
	Version      string
	Resolved     string
	Integrity    string
	Dependencies map[string]string
}

// The name ends at the first "@" after an optional scope. Berry keys carry a
// protocol that can contain more "@" signs, as in
// "typescript@patch:typescript@npm%3A^5.4.5#optional!builtin<compat/typescript>".
var yarnPkgNameRe = regexp.MustCompile(`^(@?[^@]+)@(.*)$`)

// parseYarnPackageName extracts the package name and version specifier from
// a yarn.lock map key. Keys may list multiple specifiers separated by commas
// (e.g. "has@^1.0.1, has@^1.0.3"); only the first is used.
//
// Returns (packageName, versionSpecifier, nil) on success.
// Returns ("", "", error) when the key cannot be parsed — for example
// non-package entries like "__metadata" in yarn berry (v2+) lockfiles.
func parseYarnPackageName(name string) (string, string, error) {
	pkgNames := strings.Split(name, ",")

	if len(pkgNames) == 0 {
		return "", "", errors.New("cannot parse yarn package name: " + name)
	}

	m := yarnPkgNameRe.FindStringSubmatch(strings.TrimSpace(pkgNames[0]))
	if len(m) < 3 {
		return "", "", errors.New("cannot parse yarn package name: " + name)
	}
	return m[1], m[2], nil
}
