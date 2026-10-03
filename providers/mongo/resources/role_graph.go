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

// serverRoles reads role documents from the server's rolesInfo command for the
// inheritance walk, and remembers which roles grant privileged access through
// their privileges. Results are memoized, so a role held by many users is read
// once, and rolesInfo accepts an array of role documents, so a whole level of
// the graph resolves in a single command.
type serverRoles struct {
	conn       *connection.MongoConnection
	inherits   map[roleRef][]roleRef
	privileged map[roleRef]bool
	// refused is set when the server would not show a role: the walk then
	// treats it as inheriting nothing, so a "not privileged" answer is not a
	// fact.
	refused error
}

func newServerRoles(conn *connection.MongoConnection) *serverRoles {
	return &serverRoles{
		conn:       conn,
		inherits:   map[roleRef][]roleRef{},
		privileged: map[roleRef]bool{},
	}
}

// newServerRoleLookup returns a roleLookup backed by the server's rolesInfo
// command.
func newServerRoleLookup(conn *connection.MongoConnection) roleLookup {
	return newServerRoles(conn).lookup
}

// lookup implements roleLookup. A missing privilege to read the role catalog
// degrades to "inherits nothing" and is recorded in refused; every other error
// propagates.
func (s *serverRoles) lookup(refs []roleRef) (map[roleRef][]roleRef, error) {
	missing := make([]roleRef, 0, len(refs))
	for _, ref := range refs {
		if _, done := s.inherits[ref]; !done {
			missing = append(missing, ref)
		}
	}

	if len(missing) > 0 {
		docs := make(bson.A, 0, len(missing))
		for _, ref := range missing {
			docs = append(docs, bson.D{{Key: "role", Value: ref.role}, {Key: "db", Value: ref.db}})
		}
		var res bson.M
		err := s.conn.RunAdminCommand(bson.D{
			{Key: "rolesInfo", Value: docs},
			{Key: "showPrivileges", Value: true},
			{Key: "showBuiltinRoles", Value: true},
		}, &res)
		if err != nil {
			if !isUnauthorized(err) {
				return nil, err
			}
			s.refused = err
		}
		// Seed every reference that was asked for, so a role the server did
		// not return (dropped, or not readable) is not re-requested on every
		// level of the walk.
		for _, ref := range missing {
			s.inherits[ref] = nil
		}
		for _, r := range asArray(res["roles"]) {
			m := asMap(r)
			if m == nil {
				continue
			}
			ref := roleRef{role: toStr(m["role"]), db: toStr(m["db"])}
			s.inherits[ref] = inheritedRoleRefs(m)
			s.privileged[ref] = roleDocGrantsPrivilegedAccess(m)
		}
	}

	out := make(map[roleRef][]roleRef, len(refs))
	for _, ref := range refs {
		out[ref] = s.inherits[ref]
	}
	return out, nil
}

// grantsPrivilegedAccess reports whether any of refs, already walked by
// lookup, grants privileged access through its privileges.
func (s *serverRoles) grantsPrivilegedAccess(refs []roleRef) bool {
	for _, ref := range refs {
		if s.privileged[ref] {
			return true
		}
	}
	return false
}

// userAdminActions let the holder create users or roles, or grant roles, which
// is a path to any privilege on the resource they apply to.
var userAdminActions = map[string]struct{}{
	"changePassword":               {},
	"createRole":                   {},
	"createUser":                   {},
	"dropRole":                     {},
	"dropUser":                     {},
	"grantRole":                    {},
	"revokeRole":                   {},
	"setAuthenticationRestriction": {},
}

// dataActions read or change documents.
var dataActions = map[string]struct{}{
	"find":   {},
	"insert": {},
	"update": {},
	"remove": {},
}

// privilegeIsPrivileged reports whether a single privilege document grants
// the kind of access the built-in privileged roles stand for, so a custom role
// that spells it out is flagged like the built-in one:
//   - the anyAction action, on any resource (__system)
//   - any action on the anyResource resource, which also covers system
//     collections such as admin.system.users
//   - a user or role administration action, on any resource (userAdmin)
//   - reading or writing documents in every database, {db: "", collection: ""}
//     (readAnyDatabase, readWriteAnyDatabase)
func privilegeIsPrivileged(priv bson.M) bool {
	resource := asMap(priv["resource"])
	actions := asArray(priv["actions"])
	if toBool(resource["anyResource"]) && len(actions) > 0 {
		return true
	}
	_, hasDB := resource["db"]
	_, hasColl := resource["collection"]
	everyDatabase := hasDB && hasColl && toStr(resource["db"]) == "" && toStr(resource["collection"]) == ""
	for _, a := range actions {
		action := toStr(a)
		if action == "anyAction" {
			return true
		}
		if _, ok := userAdminActions[action]; ok {
			return true
		}
		if _, ok := dataActions[action]; ok && everyDatabase {
			return true
		}
	}
	return false
}

// roleDocGrantsPrivilegedAccess checks a rolesInfo document's own and
// inherited privileges.
func roleDocGrantsPrivilegedAccess(doc bson.M) bool {
	for _, key := range []string{"privileges", "inheritedPrivileges"} {
		for _, p := range asArray(doc[key]) {
			if privilegeIsPrivileged(asMap(p)) {
				return true
			}
		}
	}
	return false
}
