// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers/mongo/connection"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// roleLookup resolves a batch of role references to the roles each of them
// inherits. A reference missing from the returned map inherits nothing that is
// visible, which is also how an unreadable role is reported.
type roleLookup func(refs []roleRef) (map[roleRef][]roleRef, error)

// resolveEffectiveRoles expands direct role grants into every role in effect.
//
// MongoDB role grants are transitive: a custom role that includes
// userAdminAnyDatabase confers it on every user holding that custom role, so a
// decision made on the direct grants alone misses the standard indirection. The
// walk is breadth-first, one lookup per level of the graph, and a visited set
// makes it safe on a cyclic graph: MongoDB permits role A to inherit role B
// while B inherits A, and an unguarded walk would never terminate. The result
// starts with the direct grants and preserves discovery order, so it is stable
// across runs.
func resolveEffectiveRoles(direct []roleRef, lookup roleLookup) ([]roleRef, error) {
	visited := make(map[roleRef]struct{}, len(direct))
	out := make([]roleRef, 0, len(direct))
	frontier := make([]roleRef, 0, len(direct))
	for _, ref := range direct {
		if _, dup := visited[ref]; dup {
			continue
		}
		visited[ref] = struct{}{}
		out = append(out, ref)
		frontier = append(frontier, ref)
	}

	for len(frontier) > 0 {
		inherited, err := lookup(frontier)
		if err != nil {
			return nil, err
		}
		next := []roleRef{}
		for _, ref := range frontier {
			for _, child := range inherited[ref] {
				if _, dup := visited[child]; dup {
					continue
				}
				visited[child] = struct{}{}
				out = append(out, child)
				next = append(next, child)
			}
		}
		frontier = next
	}
	return out, nil
}

// hasPrivilegedRole reports whether any of refs is one of the high-privilege
// built-in roles.
func hasPrivilegedRole(refs []roleRef) bool {
	for _, ref := range refs {
		if _, ok := privilegedRoles[ref.role]; ok {
			return true
		}
	}
	return false
}

// inheritedRoleRefs picks the inheritance list out of a rolesInfo document.
// With showPrivileges the server reports `inheritedRoles`, which already spans
// indirect grants; without it only the direct `roles` array is present. The
// transitive walk in resolveEffectiveRoles converges on either, so preferring
// inheritedRoles only saves levels, it does not change the result.
func inheritedRoleRefs(doc bson.M) []roleRef {
	if refs := roleRefsFromDoc(doc["inheritedRoles"]); len(refs) > 0 {
		return refs
	}
	return roleRefsFromDoc(doc["roles"])
}

// newServerRoleLookup returns a roleLookup backed by the server's rolesInfo
// command. Results are memoized across calls, so a role held by many users is
// read once, and rolesInfo accepts an array of role documents, so a whole level
// of the graph resolves in a single command.
//
// A missing privilege to read the role catalog degrades to "inherits nothing",
// matching how the rest of the provider handles an unreadable catalog; every
// other error propagates.
func newServerRoleLookup(conn *connection.MongoConnection) roleLookup {
	cache := map[roleRef][]roleRef{}
	return func(refs []roleRef) (map[roleRef][]roleRef, error) {
		missing := make([]roleRef, 0, len(refs))
		for _, ref := range refs {
			if _, done := cache[ref]; !done {
				missing = append(missing, ref)
			}
		}

		if len(missing) > 0 {
			docs := make(bson.A, 0, len(missing))
			for _, ref := range missing {
				docs = append(docs, bson.D{{Key: "role", Value: ref.role}, {Key: "db", Value: ref.db}})
			}
			var res bson.M
			err := conn.RunAdminCommand(bson.D{
				{Key: "rolesInfo", Value: docs},
				{Key: "showPrivileges", Value: true},
				{Key: "showBuiltinRoles", Value: true},
			}, &res)
			if err != nil && !isUnauthorized(err) {
				return nil, err
			}
			// Seed every reference that was asked for, so a role the server did
			// not return (dropped, or not readable) is not re-requested on every
			// level of the walk.
			for _, ref := range missing {
				cache[ref] = nil
			}
			for _, r := range asArray(res["roles"]) {
				m := asMap(r)
				if m == nil {
					continue
				}
				cache[roleRef{role: toStr(m["role"]), db: toStr(m["db"])}] = inheritedRoleRefs(m)
			}
		}

		out := make(map[roleRef][]roleRef, len(refs))
		for _, ref := range refs {
			out[ref] = cache[ref]
		}
		return out, nil
	}
}
