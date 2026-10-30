// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/types"
)

// Reachability from an asset root (ADR 031) gets asked in two different shapes,
// and they are not the same question:
//
//   - RootEmbeds asks whether a resource is the root or part of its embed chain
//     (`os.linux` -> `os.unix` -> `os.base`). Members of those resources are the
//     ones a rooted query names directly, which is what makes `os.base.hostname`
//     spellable as `hostname`.
//   - RootReachable asks whether a resource can be addressed from any root at
//     all, by any path. `sshd.config` is not in an embed chain, but `_.sshd` is
//     a member of a root, so `_.sshd.config` resolves.
//
// The first answers "can this be shortened", the second "does this exist for a
// rooted user". Both live here so the compiler and the schema generator agree.

// RootEmbeds reports whether name is root itself or sits in its embed chain.
func RootEmbeds(schema ResourcesSchema, root string, name string) bool {
	if schema == nil || root == "" || name == "" {
		return false
	}

	seen := map[string]struct{}{}
	var walk func(string) bool
	walk = func(current string) bool {
		if current == name {
			return true
		}
		if _, ok := seen[current]; ok {
			return false
		}
		seen[current] = struct{}{}

		info := schema.Lookup(current)
		if info == nil {
			return false
		}
		for _, f := range info.Fields {
			if !f.IsEmbedded {
				continue
			}
			if child := types.ResourceOf(types.Type(f.Type)); child != "" && walk(child) {
				return true
			}
		}
		return false
	}
	return walk(root)
}

// RootReachable reports whether name can still be addressed once the asset root
// is the namespace (ADR 031 v15): it is a root, or something reachable from one
// by following fields. `sshd.config` is not in any embed chain, but `_.sshd`
// is a member of a root and `sshd` has a `config` field, so `_.sshd.config`
// resolves and the name survives the cutover. The bridging namespace node `os`
// does not: nothing has a field of that type, which is exactly why `os.hostname`
// stops resolving in v15 and this whole migration exists.
//
// A resource marked `@global` is reachable by definition - it is declared as not
// needing a root.
//
// Returns true when the schema declares no roots at all: there is nothing to be
// outside of, so the question is not answerable and a caller must not read a
// false as "unreachable".
//
// This is the build-time counterpart to what the compiler records per bundle as
// `unrooted_resources`. That one asks a narrower version - only against the
// provider's own declared root, for one resource a query actually reached -
// because it measures migration progress rather than validating a schema.
func RootReachable(schema ResourcesSchema, name string) bool {
	if schema == nil || name == "" {
		return false
	}

	roots := rootsOf(schema)
	if len(roots) == 0 {
		return true
	}

	info := schema.Lookup(name)
	if info == nil {
		return false
	}
	if info.GetGlobal() {
		return true
	}
	if _, ok := roots[name]; ok {
		return true
	}

	// An aliased resource is reachable under the alias name, and the alias and
	// the resource it names are the same resource - so the question has to be
	// asked about canonical ids, not map keys. `alias microsoft.exchangeonline
	// = ms365.exchangeonline` puts the alias on the root; asking whether
	// `ms365.exchangeonline` is reachable has to answer yes.
	canonical := func(n string) string {
		if info := schema.Lookup(n); info != nil && info.Id != "" {
			return info.Id
		}
		return n
	}
	want := canonical(name)

	seen := map[string]struct{}{}
	queue := make([]string, 0, len(roots))
	for rootName := range roots {
		queue = append(queue, rootName)
		seen[rootName] = struct{}{}
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		currentInfo := schema.Lookup(current)
		if currentInfo == nil {
			continue
		}
		for _, f := range currentInfo.Fields {
			if f.IsPrivate {
				continue
			}
			// Both `foo bar.baz` and `foo []bar.baz` reach bar.baz; the list
			// wrapper is not a different destination. ResourceOf unwraps it and
			// answers "" for a plain string, where ResourceName would panic.
			child := types.ResourceOf(types.Type(f.Type))
			if child == "" {
				continue
			}
			if child == name || canonical(child) == want {
				return true
			}
			if _, ok := seen[child]; ok {
				continue
			}
			seen[child] = struct{}{}
			queue = append(queue, child)
		}
	}
	return false
}

// rootsOf collects the resources declared as asset roots, skipping the aliases
// under which a resource can also appear in the schema map.
func rootsOf(schema ResourcesSchema) map[string]*ResourceInfo {
	res := map[string]*ResourceInfo{}
	for name, info := range schema.AllResources() {
		if info == nil || !info.GetRoot() || name != info.Id {
			continue
		}
		res[name] = info
	}
	return res
}
