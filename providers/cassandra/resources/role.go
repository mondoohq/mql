// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"

	"github.com/gocql/gocql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cassandra/connection"
	"go.mondoo.com/mql/types"
)

func (r *mqlCassandraCluster) roles() ([]any, error) {
	conn := cassandraConnection(r.MqlRuntime)
	session, err := conn.Session()
	if err != nil {
		return nil, err
	}

	type roleRow struct {
		name        string
		canLogin    bool
		isSuperuser bool
		memberOf    []string
		hasPassword bool
	}
	var rows []roleRow
	// system_auth is replicated with SimpleStrategy by default, so in a
	// multi-DC cluster the connected DC may hold no replica of a role row and
	// LOCAL_ONE cannot be met. ONE reads from any replica.
	iter := session.Query(`SELECT role, can_login, is_superuser, member_of, salted_hash FROM system_auth.roles`).Consistency(gocql.One).Iter()
	var name string
	var canLogin, isSuperuser bool
	var memberOf []string
	var saltedHash string
	for iter.Scan(&name, &canLogin, &isSuperuser, &memberOf, &saltedHash) {
		mo := make([]string, len(memberOf))
		copy(mo, memberOf)
		rows = append(rows, roleRow{
			name:        name,
			canLogin:    canLogin,
			isSuperuser: isSuperuser,
			memberOf:    mo,
			// salted_hash is the bcrypt hash; expose only its presence, never the value.
			hasPassword: saltedHash != "",
		})
	}
	if err := iter.Close(); err != nil {
		// Reading all roles needs SELECT on system_auth (or superuser). A
		// denial is an error: an empty list would pass every check on roles.
		// On an AllowAll cluster the roles table is simply empty.
		if connection.IsUnauthorized(err) {
			if !plugin.StructuredErrors() {
				return []any{}, nil
			}
			return nil, refused(err, "SELECT ON system_auth.roles")
		}
		return nil, err
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })

	direct := make(map[string]bool, len(rows))
	grantedTo := make(map[string][]string, len(rows))
	for _, row := range rows {
		direct[row.name] = row.isSuperuser
		grantedTo[row.name] = row.memberOf
	}
	effective := effectiveSuperusers(direct, grantedTo)

	serverID := r.__id
	list := []any{}
	for _, row := range rows {
		res, err := CreateResource(r.MqlRuntime, "cassandra.role", map[string]*llx.RawData{
			"__id":                 llx.StringData(serverID + "/role/" + row.name),
			"name":                 llx.StringData(row.name),
			"canLogin":             llx.BoolData(row.canLogin),
			"isSuperuser":          llx.BoolData(row.isSuperuser),
			"isEffectiveSuperuser": llx.BoolData(effective[row.name]),
			"hasPassword":          llx.BoolData(row.hasPassword),
			"memberOf":             llx.ArrayData(toAnySlice(row.memberOf), types.String),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlCassandraRole) permissions() ([]any, error) {
	conn := cassandraConnection(r.MqlRuntime)
	session, err := conn.Session()
	if err != nil {
		return nil, err
	}

	type permRow struct {
		resource    string
		permissions []string
	}
	var rows []permRow
	iter := session.Query(`SELECT resource, permissions FROM system_auth.role_permissions WHERE role = ?`, r.Name.Data).Consistency(gocql.One).Iter()
	var resource string
	var perms []string
	for iter.Scan(&resource, &perms) {
		p := make([]string, len(perms))
		copy(p, perms)
		sort.Strings(p)
		rows = append(rows, permRow{resource: resource, permissions: p})
	}
	if err := iter.Close(); err != nil {
		if connection.IsUnauthorized(err) {
			if !plugin.StructuredErrors() {
				return []any{}, nil
			}
			return nil, refused(err, "SELECT ON system_auth.role_permissions")
		}
		return nil, err
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].resource < rows[j].resource })

	list := []any{}
	for _, row := range rows {
		// resource is unique per role (role_permissions PK is (role, resource)),
		// so it makes a stable id regardless of the order rows are returned in.
		res, err := CreateResource(r.MqlRuntime, "cassandra.role.permission", map[string]*llx.RawData{
			"__id":        llx.StringData(r.__id + "/perm/" + row.resource),
			"resource":    llx.StringData(row.resource),
			"permissions": llx.ArrayData(toAnySlice(row.permissions), types.String),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

// effectiveSuperusers resolves superuser status the way Cassandra does: a role
// is a superuser when it has the flag itself or when any role granted to it,
// transitively, has it. grantedTo maps each role to the roles granted to it.
// Grants can form a cycle, so each role walks its own grant closure with a
// visited set; role counts are small enough that a walk per role is cheap.
func effectiveSuperusers(direct map[string]bool, grantedTo map[string][]string) map[string]bool {
	out := make(map[string]bool, len(direct))
	for name := range direct {
		visited := map[string]bool{name: true}
		queue := []string{name}
		for len(queue) > 0 && !out[name] {
			cur := queue[0]
			queue = queue[1:]
			if direct[cur] {
				out[name] = true
				break
			}
			for _, parent := range grantedTo[cur] {
				if !visited[parent] {
					visited[parent] = true
					queue = append(queue, parent)
				}
			}
		}
	}
	return out
}
