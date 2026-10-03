// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"database/sql"
	"fmt"
	"slices"
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/clickhousedb/connection"
)

// mqlClickhousedbInstanceInternal caches system.role_grants, read once for
// every user and role on the server.
type mqlClickhousedbInstanceInternal struct {
	roleGrantsOnce sync.Once
	userRoles      map[string][]string
	roleRoles      map[string][]string
	roleGrantsErr  error
}

// mqlClickhousedbUserInternal points back at the instance the user was listed
// from, so its roles resolve through the instance's role list.
type mqlClickhousedbUserInternal struct {
	cacheInstance *mqlClickhousedbInstance
}

// mqlClickhousedbRoleInternal points back at the instance the role was listed
// from.
type mqlClickhousedbRoleInternal struct {
	cacheInstance *mqlClickhousedbInstance
}

// roleGrantRow is one row of system.role_grants: a role granted to either a
// user or a role.
type roleGrantRow struct {
	user, role, granted string
}

// groupRoleGrants files role grants by grantee, each list sorted by role name.
func groupRoleGrants(rows []roleGrantRow) (users, roles map[string][]string) {
	users = map[string][]string{}
	roles = map[string][]string{}
	for _, row := range rows {
		switch {
		case row.user != "":
			users[row.user] = append(users[row.user], row.granted)
		case row.role != "":
			roles[row.role] = append(roles[row.role], row.granted)
		}
	}
	for _, m := range []map[string][]string{users, roles} {
		for k := range m {
			slices.Sort(m[k])
		}
	}
	return users, roles
}

func (r *mqlClickhousedbInstance) roleGrants() (map[string][]string, map[string][]string, error) {
	r.roleGrantsOnce.Do(func() {
		conn := clickhousedbConnection(r.MqlRuntime)
		db, err := conn.Client()
		if err != nil {
			r.roleGrantsErr = err
			return
		}
		rows, err := db.QueryContext(conn.Context(),
			`SELECT user_name, role_name, granted_role_name FROM system.role_grants`)
		if err != nil {
			r.roleGrantsErr = err
			return
		}
		defer rows.Close()
		var list []roleGrantRow
		for rows.Next() {
			var user, role sql.NullString
			var granted string
			if err := rows.Scan(&user, &role, &granted); err != nil {
				r.roleGrantsErr = err
				return
			}
			list = append(list, roleGrantRow{user: user.String, role: role.String, granted: granted})
		}
		if err := rows.Err(); err != nil {
			r.roleGrantsErr = err
			return
		}
		r.userRoles, r.roleRoles = groupRoleGrants(list)
	})
	return r.userRoles, r.roleRoles, r.roleGrantsErr
}

// rolesNamed resolves role names to the instance's role resources. A granted
// role the instance does not list is skipped: it cannot be, since a grant
// names an existing role, unless the role list itself is filtered.
func (r *mqlClickhousedbInstance) rolesNamed(names []string) ([]any, error) {
	all := r.GetRoles()
	if all.Error != nil {
		return nil, all.Error
	}
	byName := make(map[string]any, len(all.Data))
	for _, x := range all.Data {
		role := x.(*mqlClickhousedbRole)
		byName[role.Name.Data] = role
	}
	list := []any{}
	for _, n := range names {
		if role, ok := byName[n]; ok {
			list = append(list, role)
		}
	}
	return list, nil
}

// heldRoles returns the roles granted to a user (forUser) or a role. A refusal
// to read system.role_grants keeps the v13 empty answer unless
// StructuredErrors is on.
func heldRoles(inst *mqlClickhousedbInstance, name string, forUser bool) ([]any, error) {
	if inst == nil {
		return nil, fmt.Errorf("clickhousedb: %s was not listed from an instance, its roles cannot be resolved", name)
	}
	users, roles, err := inst.roleGrants()
	if err != nil {
		if connection.IsPermissionError(err) && !plugin.StructuredErrors() {
			return []any{}, nil
		}
		return nil, err
	}
	m := roles
	if forUser {
		m = users
	}
	return inst.rolesNamed(m[name])
}

func (r *mqlClickhousedbUser) roles() ([]any, error) {
	return heldRoles(r.cacheInstance, r.Name.Data, true)
}

func (r *mqlClickhousedbRole) roles() ([]any, error) {
	return heldRoles(r.cacheInstance, r.Name.Data, false)
}
