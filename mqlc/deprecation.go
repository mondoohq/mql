// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

// A `@replaced_by` target is stored as the schema path of the replacement
// (`os.base.hostname`) because that is the only form a schema-to-schema
// consumer - a lens, a diff, a doc generator - can use. It is not what a user
// types: once a query is rooted (ADR 031), `os.base.hostname` is reached as
// `hostname`, and telling someone to write the schema path would be telling
// them to write something that does not compile in v15.
//
// So the annotation records the path and this renders the spelling, against
// whatever root the compile had. Without a root there is nothing to shorten
// against and the path is the honest answer.

// DeprecationNotices turns the deprecated names a bundle records into lines a
// user can act on. Returns nil when there is nothing to say, which is the
// common case.
func DeprecationNotices(bundle *llx.CodeBundle, schema resources.ResourcesSchema) []string {
	if bundle == nil || len(bundle.DeprecatedUses) == 0 {
		return nil
	}

	res := make([]string, 0, len(bundle.DeprecatedUses))
	for _, use := range bundle.DeprecatedUses {
		if use == nil || use.From == "" || use.To == "" {
			continue
		}
		// Only the most specific notice survives. Reading `os.hostname`
		// records the deprecated field and the deprecated resource it hangs
		// off, and saying both is saying the same thing twice: the field
		// notice already tells the user what to type instead. The resource
		// notice is for the query that names only the resource.
		if supersededBy(bundle.DeprecatedUses, use.From) {
			continue
		}
		res = append(res, use.From+" has migrated to "+RelativeToRoot(schema, bundle.AssetRoot, use.To))
	}
	if len(res) == 0 {
		return nil
	}
	return res
}

// RelativeToRoot renders a schema path the way a query rooted at root would
// spell it: `os.base.hostname` under any OS root is `hostname`, and the root
// itself is `_`. A path that root cannot reach is returned unchanged - a
// shortened name that does not resolve would be worse than a long one that
// does.
func RelativeToRoot(schema resources.ResourcesSchema, root string, target string) string {
	if root == "" || target == "" || schema == nil {
		return target
	}
	if resources.RootEmbeds(schema, root, target) {
		return "_"
	}

	owner, field := splitPath(target)
	if field == "" || !resources.RootEmbeds(schema, root, owner) {
		return target
	}
	if info := schema.Lookup(owner); info != nil {
		if f, ok := info.Fields[field]; ok && !f.IsPrivate {
			return field
		}
	}
	return target
}

// splitPath splits a schema path into the resource that owns the last segment
// and the segment itself. Resource names are dotted, so only the final segment
// can be a field.
func splitPath(path string) (string, string) {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '.' {
			return path[:i], path[i+1:]
		}
	}
	return path, ""
}

// supersededBy reports whether some other recorded use is a more specific name
// than this one - `os.hostname` against `os`.
func supersededBy(uses []*llx.DeprecatedUse, name string) bool {
	prefix := name + "."
	for _, other := range uses {
		if other == nil || other.From == name {
			continue
		}
		if strings.HasPrefix(other.From, prefix) {
			return true
		}
	}
	return false
}
