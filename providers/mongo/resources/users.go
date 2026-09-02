// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// roleRefsFromDoc extracts {role, db} grants from a document's `roles` array.
func roleRefsFromDoc(rolesVal any) []roleRef {
	arr := asArray(rolesVal)
	refs := make([]roleRef, 0, len(arr))
	for _, r := range arr {
		m := asMap(r)
		if m == nil {
			continue
		}
		refs = append(refs, roleRef{role: toStr(m["role"]), db: toStr(m["db"])})
	}
	return refs
}

func (r *mqlMongoInstance) users() ([]any, error) {
	conn := mongoConnection(r.MqlRuntime)
	var res bson.M
	// usersInfo with forAllDBs returns every user across databases; it requires
	// a privilege, so treat an authorization error as no visible users and
	// propagate everything else.
	if err := conn.RunAdminCommand(bson.D{{Key: "usersInfo", Value: bson.D{{Key: "forAllDBs", Value: true}}}}, &res); err != nil {
		if isUnauthorized(err) {
			return []any{}, nil
		}
		return nil, err
	}

	users := asArray(res["users"])
	serverID := r.__id
	// One memoized lookup for the whole listing: users share roles, so the role
	// graph is read once no matter how many accounts reference it.
	lookup := newServerRoleLookup(conn)
	list := []any{}
	for _, u := range users {
		m := asMap(u)
		if m == nil {
			continue
		}
		user := toStr(m["user"])
		db := toStr(m["db"])
		refs := roleRefsFromDoc(m["roles"])

		// Role grants are transitive, so the privilege decision is made on the
		// inheritance-expanded set rather than on the direct grants alone.
		effective, err := resolveEffectiveRoles(refs, lookup)
		if err != nil {
			return nil, err
		}
		privileged := hasPrivilegedRole(effective)

		mechanisms := []any{}
		for _, x := range asArray(m["mechanisms"]) {
			mechanisms = append(mechanisms, toStr(x))
		}

		res, err := CreateResource(r.MqlRuntime, "mongo.user", map[string]*llx.RawData{
			"__id":         llx.StringData(userResourceID(serverID, db, user)),
			"user":         llx.StringData(user),
			"db":           llx.StringData(db),
			"userId":       llx.StringData(toStr(m["_id"])),
			"mechanisms":   llx.ArrayData(mechanisms, types.String),
			"isPrivileged": llx.BoolData(privileged),
		})
		if err != nil {
			return nil, err
		}
		mqlUser := res.(*mqlMongoUser)
		mqlUser.cacheRoleRefs = refs
		mqlUser.cacheEffectiveRefs = effective
		mqlUser.effectiveResolved = true
		list = append(list, mqlUser)
	}
	return list, nil
}

func (r *mqlMongoUser) roles() ([]any, error) {
	return r.roleResources(r.cacheRoleRefs)
}

func (r *mqlMongoUser) effectiveRoles() ([]any, error) {
	if !r.effectiveResolved {
		refs, err := resolveEffectiveRoles(r.cacheRoleRefs, newServerRoleLookup(mongoConnection(r.MqlRuntime)))
		if err != nil {
			return nil, err
		}
		r.cacheEffectiveRefs = refs
		r.effectiveResolved = true
	}
	return r.roleResources(r.cacheEffectiveRefs)
}

// roleResources turns role references into mongo.role resources.
func (r *mqlMongoUser) roleResources(refs []roleRef) ([]any, error) {
	serverID := mongoConnection(r.MqlRuntime).ServerID()
	list := []any{}
	for _, ref := range refs {
		role, err := newMongoRole(r.MqlRuntime, serverID, ref.db, ref.role)
		if err != nil {
			return nil, err
		}
		list = append(list, role)
	}
	return list, nil
}
