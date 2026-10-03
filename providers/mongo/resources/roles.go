// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mongo/connection"
	"go.mondoo.com/mql/types"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func (r *mqlMongoInstance) roles() ([]any, error) {
	conn := mongoConnection(r.MqlRuntime)
	client, err := conn.Client()
	if err != nil {
		return nil, err
	}
	dbs, err := client.ListDatabaseNames(mongoContext(), bson.D{})
	if err != nil {
		return nil, err
	}
	// The admin database also holds cluster-wide custom roles.
	if !containsStr(dbs, "admin") {
		dbs = append(dbs, "admin")
	}
	// A database that holds a custom role but no data is not returned by
	// listDatabases, so its roles would be missed. Custom role definitions all
	// live in admin.system.roles; union in every database named there so those
	// roles are enumerated too.
	for _, db := range roleDatabases(conn) {
		if !containsStr(dbs, db) {
			dbs = append(dbs, db)
		}
	}

	serverID := conn.ServerID()
	seen := map[string]struct{}{}
	list := []any{}
	var refusal error
	readable := 0
	for _, db := range dbs {
		var res bson.M
		// Custom (non-built-in) roles defined in this database. Needs the
		// viewRole action on it; a database the account cannot read is skipped
		// as long as another one answers.
		if err := conn.RunCommand(db, bson.D{
			{Key: "rolesInfo", Value: 1},
			{Key: "showBuiltinRoles", Value: false},
		}, &res); err != nil {
			if isUnauthorized(err) {
				refusal = err
				continue
			}
			return nil, err
		}
		readable++
		roles := asArray(res["roles"])
		for _, r0 := range roles {
			m := asMap(r0)
			if m == nil {
				continue
			}
			roleDB := toStr(m["db"])
			roleName := toStr(m["role"])
			key := roleDB + "." + roleName
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			role, err := newMongoRole(r.MqlRuntime, serverID, roleDB, roleName)
			if err != nil {
				return nil, err
			}
			list = append(list, role)
		}
	}
	// Not a single database answered: the account cannot read roles at all,
	// and an empty list would pass every check on them.
	if readable == 0 && refusal != nil {
		if !plugin.StructuredErrors() {
			return []any{}, nil
		}
		return nil, classifyRefusal(refusal, "viewRole")
	}
	return list, nil
}

// rolesInfoDoc fetches the full rolesInfo document for this role (privileges +
// inherited roles), run against the role's own database.
func (r *mqlMongoRole) rolesInfoDoc() (bson.M, error) {
	conn := mongoConnection(r.MqlRuntime)
	var res bson.M
	err := conn.RunCommand(r.Db.Data, bson.D{
		{Key: "rolesInfo", Value: bson.D{{Key: "role", Value: r.Role.Data}, {Key: "db", Value: r.Db.Data}}},
		{Key: "showPrivileges", Value: true},
		{Key: "showBuiltinRoles", Value: true},
	}, &res)
	if err != nil {
		return nil, err
	}
	roles := asArray(res["roles"])
	if len(roles) == 0 {
		return nil, nil
	}
	return asMap(roles[0]), nil
}

func (r *mqlMongoRole) privileges() ([]any, error) {
	doc, err := r.rolesInfoDoc()
	if err != nil || doc == nil {
		return []any{}, err
	}
	privs := asArray(doc["privileges"])
	list := []any{}
	for i, p := range privs {
		m := asMap(p)
		if m == nil {
			continue
		}
		resource := asMap(m["resource"])
		actions := []any{}
		for _, a := range asArray(m["actions"]) {
			actions = append(actions, toStr(a))
		}
		res, err := CreateResource(r.MqlRuntime, "mongo.role.privilege", map[string]*llx.RawData{
			"__id":       llx.StringData(r.__id + "/priv/" + intToStr(int64(i))),
			"database":   llx.StringData(toStr(resource["db"])),
			"collection": llx.StringData(toStr(resource["collection"])),
			"cluster":    llx.BoolData(toBool(resource["cluster"])),
			"actions":    llx.ArrayData(actions, types.String),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlMongoRole) inheritedRoles() ([]any, error) {
	doc, err := r.rolesInfoDoc()
	if err != nil || doc == nil {
		return []any{}, err
	}
	serverID := mongoConnection(r.MqlRuntime).ServerID()
	list := []any{}
	for _, ref := range roleRefsFromDoc(doc["inheritedRoles"]) {
		role, err := newMongoRole(r.MqlRuntime, serverID, ref.db, ref.role)
		if err != nil {
			return nil, err
		}
		list = append(list, role)
	}
	return list, nil
}

// roleDatabases returns every database that has at least one custom role
// defined, read from the admin.system.roles catalog. It tolerates a missing
// read privilege (returning nothing) so role enumeration degrades gracefully.
func roleDatabases(conn *connection.MongoConnection) []string {
	var res bson.M
	if err := conn.RunAdminCommand(bson.D{
		{Key: "distinct", Value: "system.roles"},
		{Key: "key", Value: "db"},
	}, &res); err != nil {
		return nil
	}
	out := []string{}
	for _, v := range asArray(res["values"]) {
		if db := toStr(v); db != "" {
			out = append(out, db)
		}
	}
	return out
}

func containsStr(s []string, want string) bool {
	for _, x := range s {
		if x == want {
			return true
		}
	}
	return false
}
