// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packagelockjson

import (
	"encoding/json"
	"sort"
	"strings"

	"go.mondoo.com/mql/v13/providers/os/resources/languages"
	"go.mondoo.com/mql/v13/providers/os/resources/languages/javascript"
)

// scopeOf maps an npm lock package entry to a languages package scope, from
// npm's per-package flags (lockfileVersion 2+):
//
//   - dev=true, devOptional=false → PackageScopeDev (strictly dev-only)
//   - devOptional=true (with or without dev) → PackageScopeProd: npm sets this
//     when a package is reachable both as a devDependency and as an optional
//     production dependency, so it can be in the deployed tree — we keep it.
//   - dev=false → PackageScopeProd
//
// Reporting devOptional as prod is deliberately conservative: it never hides a
// package that might ship in production (an under-report would be worse than the
// occasional dev-and-optional package counted as prod).
func scopeOf(pkg packageLockPackage) string {
	if pkg.Dev && !pkg.DevOptional {
		return languages.PackageScopeDev
	}
	return languages.PackageScopeProd
}

// maxNodeModulesDepth bounds the resolveDepPurl walk-up. Real npm trees nest only
// a handful of levels (hoisting flattens most to the root); this ceiling stops a
// crafted lockfile with a pathologically deep `.../node_modules/x/node_modules/x`
// key from turning edge resolution into superlinear CPU (a per-scan DoS on
// untrusted repos). Edges that would resolve only below the ceiling are dropped.
const maxNodeModulesDepth = 64

// purlIndex maps every `packages` install-path key to its component purl, built
// once per lockfile so edge resolution can reference a target's purl without
// rebuilding it per incoming edge.
func (p *packageLock) purlIndex() map[string]string {
	idx := make(map[string]string, len(p.Packages))
	for k, v := range p.Packages {
		name := packageLockPackageName(k)
		if k == "" {
			name = v.Name
		}
		idx[k] = javascript.NewPackageUrl(name, v.Version)
	}
	return idx
}

// dependsOnRefs resolves a package entry's `dependencies` (name→version-range)
// to the refs (purls) of the resolved packages, following npm's hoisting rules
// from fromPath. Returns sorted, deduplicated purls; skips deps that do not
// resolve to a `packages` entry. This yields the package→package edges the
// lockfile encodes (lockfileVersion 2+).
func dependsOnRefs(pkgs map[string]packageLockPackage, pathToPurl map[string]string, fromPath string, deps map[string]string) []string {
	if len(deps) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var refs []string
	for name := range deps {
		if ref := resolveDepPurl(pkgs, pathToPurl, fromPath, name); ref != "" && !seen[ref] {
			seen[ref] = true
			refs = append(refs, ref)
		}
	}
	sort.Strings(refs)
	return refs
}

// resolveDepPurl finds the package entry that satisfies depName as required from
// fromPath, per npm resolution: try fromPath/node_modules/depName, then walk up
// the node_modules chain to the root. Returns the resolved package's purl (from
// the prebuilt index, matching the target node's own Purl for a self-consistent
// graph), or "" when no entry is found within maxNodeModulesDepth levels.
func resolveDepPurl(pkgs map[string]packageLockPackage, pathToPurl map[string]string, fromPath, depName string) string {
	base := fromPath
	for depth := 0; depth <= maxNodeModulesDepth; depth++ {
		cand := "node_modules/" + depName
		if base != "" {
			cand = base + "/node_modules/" + depName
		}
		if _, ok := pkgs[cand]; ok {
			return pathToPurl[cand]
		}
		if base == "" {
			return ""
		}
		if idx := strings.LastIndex(base, "/node_modules/"); idx >= 0 {
			base = base[:idx]
		} else {
			base = ""
		}
	}
	return ""
}

// packageLock is the struct to represent the package.lock file
// see https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json
type packageLock struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	LockfileVersion int    `json:"lockfileVersion"`
	Requires        bool   `json:"requires"`
	// Packages maps package locations to an object containing the information about that package,
	// root project is typically listed with a key of ""
	Packages map[string]packageLockPackage `json:"packages"`
	// Dependencies contains legacy data for supporting versions of npm that use lockfileVersion: 1 or lower.
	// We can ignore that for lockfileVersion: 2+
	Dependencies map[string]packageLockDependency `json:"dependencies"`

	// evidence is a list of file paths where the package-lock was found
	evidence []string `json:"-"`
}

type packageLockDependency struct {
	Version   string `json:"version"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Dev       bool   `json:"dev"`
}

type packageLockPackage struct {
	Name      string             `json:"name"`
	Version   string             `json:"version"`
	Resolved  string             `json:"resolved"`
	Integrity string             `json:"integrity"`
	License   packageLockLicense `json:"license"`
	// Dev marks a development-only dependency (npm lockfileVersion 2+): present
	// in the tree only for devDependencies / their closure, not the production
	// runtime. Also DevOptional (a package needed both as dev and optionally in
	// prod) — treated as prod, since it can be in the production tree.
	Dev          bool              `json:"dev"`
	DevOptional  bool              `json:"devOptional"`
	Dependencies map[string]string `json:"dependencies"`
}

type packageLockLicense []string

// UnmarshalJSON is a custom unmarshaler for the packageLockLicense type. It allows to handle the license field
// which could be either a string or an array.
func (l *packageLockLicense) UnmarshalJSON(data []byte) (err error) {

	var slice []string
	if err := json.Unmarshal(data, &slice); err == nil {
		*l = slice
		return nil
	}

	var single string
	if err = json.Unmarshal(data, &single); err == nil {
		*l = []string{single}
		return nil
	}

	// if it's neither a string nor an array, ignore it
	return nil
}

// packageLockPackageName extracts the package name from a lockfileVersion 2+
// `packages` key. Those keys are install paths — "node_modules/<name>", or for a
// nested (non-hoisted) copy "node_modules/<parent>/node_modules/<name>" — so the
// real package name is everything after the LAST "node_modules/" segment.
// Trimming only the prefix left nested packages named by their full path (e.g.
// "@babel/core/node_modules/ms") and, fed to NewPackageUrl, produced a purl built
// from the path rather than the name.
func packageLockPackageName(path string) string {
	if i := strings.LastIndex(path, "node_modules/"); i >= 0 {
		return path[i+len("node_modules/"):]
	}
	return path
}
