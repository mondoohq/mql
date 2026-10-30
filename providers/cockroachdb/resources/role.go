// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// roleRow is one role from pg_catalog.pg_roles, which every user can read.
type roleRow struct {
	name       string
	canLogin   bool
	isAdmin    bool
	validUntil *time.Time
	memberOf   []string
}

// roleRows lists every role once per connection. pg_roles reports rolsuper
// for the admin role and every role that is a member of it, directly or
// through other roles; pg_auth_members holds the direct memberships.
func roleRows(runtime *plugin.Runtime) ([]roleRow, error) {
	v, err := crdbConnection(runtime).Memo("roles", func() (any, error) {
		rows, err := query(runtime, `SELECT r.rolname, r.rolcanlogin, r.rolsuper, r.rolvaliduntil,
			COALESCE(ARRAY(SELECT g.rolname FROM pg_catalog.pg_auth_members m
				JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
				WHERE m.member = r.oid ORDER BY g.rolname), ARRAY[]::STRING[])
			FROM pg_catalog.pg_roles r ORDER BY r.rolname`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		list := []roleRow{}
		for rows.Next() {
			var row roleRow
			if err := rows.Scan(&row.name, &row.canLogin, &row.isAdmin, &row.validUntil, &row.memberOf); err != nil {
				return nil, err
			}
			row.validUntil = utc(row.validUntil)
			list = append(list, row)
		}
		return list, rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return v.([]roleRow), nil
}

func roleArgs(row roleRow) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"name":       llx.StringData(row.name),
		"canLogin":   llx.BoolData(row.canLogin),
		"isAdmin":    llx.BoolData(row.isAdmin),
		"validUntil": llx.TimeDataPtr(row.validUntil),
	}
}

type mqlCockroachdbRoleInternal struct {
	memberOfNames []string
}

func (r *mqlCockroachdbRole) id() (string, error) {
	return "cockroachdb.role/" + r.Name.Data, nil
}

// initCockroachdbRole resolves a role by name, for typed references such as
// a database owner.
func initCockroachdbRole(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	raw, ok := args["name"]
	if !ok {
		return nil, nil, fmt.Errorf("cockroachdb.role needs a name")
	}
	name, _ := raw.Value.(string)
	rows, err := roleRows(runtime)
	if err != nil {
		return nil, nil, err
	}
	for _, row := range rows {
		if row.name == name {
			return roleArgs(row), nil, nil
		}
	}
	return nil, nil, fmt.Errorf("cockroachdb.role %q not found", name)
}

func (r *mqlCockroachdbCluster) roles() ([]any, error) {
	rows, err := roleRows(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := []any{}
	for _, row := range rows {
		res, err := CreateResource(r.MqlRuntime, "cockroachdb.role", roleArgs(row))
		if err != nil {
			return nil, err
		}
		res.(*mqlCockroachdbRole).memberOfNames = row.memberOf
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlCockroachdbRole) memberOf() ([]any, error) {
	names := r.memberOfNames
	if names == nil {
		rows, err := roleRows(r.MqlRuntime)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			if row.name == r.Name.Data {
				names = row.memberOf
				break
			}
		}
	}
	list := []any{}
	for _, name := range names {
		res, err := NewResource(r.MqlRuntime, "cockroachdb.role", map[string]*llx.RawData{
			"name": llx.StringData(name),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

// roleOptions returns every role's options as SHOW USERS reports them. SHOW
// USERS reads system.users, which needs the admin role.
func roleOptions(runtime *plugin.Runtime) (map[string][]string, error) {
	v, err := crdbConnection(runtime).Memo("roleOptions", func() (any, error) {
		rows, err := query(runtime, `SELECT username, options FROM [SHOW USERS]`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := map[string][]string{}
		for rows.Next() {
			var name string
			var options []string
			if err := rows.Scan(&name, &options); err != nil {
				return nil, err
			}
			out[name] = options
		}
		return out, rows.Err()
	})
	if err != nil {
		return nil, refused(err, "admin role (SELECT ON system.users)")
	}
	return v.(map[string][]string), nil
}

func (r *mqlCockroachdbRole) options() ([]any, error) {
	options, err := roleOptions(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return toAnySlice(options[r.Name.Data]), nil
}

// resolveRole resolves a role by name for an owner or grantee reference. A
// name that is no role, such as the "public" pseudo-role, resolves to null.
func resolveRole(runtime *plugin.Runtime, name string, field *plugin.TValue[*mqlCockroachdbRole]) (*mqlCockroachdbRole, error) {
	rows, err := roleRows(runtime)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.name == name {
			res, err := NewResource(runtime, "cockroachdb.role", map[string]*llx.RawData{
				"name": llx.StringData(name),
			})
			if err != nil {
				return nil, err
			}
			return res.(*mqlCockroachdbRole), nil
		}
	}
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// passwordMethods returns how each role's password is stored. The hash is
// classified by CockroachDB itself, so no hash leaves the server: SCRAM
// hashes start with "SCRAM-SHA-256$", bcrypt hashes with "$".
func passwordMethods(runtime *plugin.Runtime) (map[string]string, error) {
	v, err := crdbConnection(runtime).Memo("passwords", func() (any, error) {
		rows, err := query(runtime, `SELECT username, CASE
			WHEN "hashedPassword" IS NULL OR length("hashedPassword") = 0 THEN ''
			WHEN substring("hashedPassword", 1, 14) = b'SCRAM-SHA-256$' THEN 'scram-sha-256'
			WHEN substring("hashedPassword", 1, 1) = b'$' THEN 'crdb-bcrypt'
			ELSE 'unknown' END
			FROM system.users`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		methods := map[string]string{}
		for rows.Next() {
			var name, method string
			if err := rows.Scan(&name, &method); err != nil {
				return nil, err
			}
			methods[name] = method
		}
		return methods, rows.Err()
	})
	if err != nil {
		return nil, refused(err, "admin role (SELECT ON system.users)")
	}
	return v.(map[string]string), nil
}

func (r *mqlCockroachdbRole) hasPassword() (bool, error) {
	methods, err := passwordMethods(r.MqlRuntime)
	if err != nil {
		return false, err
	}
	return methods[r.Name.Data] != "", nil
}

func (r *mqlCockroachdbRole) passwordHashMethod() (string, error) {
	methods, err := passwordMethods(r.MqlRuntime)
	if err != nil {
		return "", err
	}
	return methods[r.Name.Data], nil
}

// allRoles is the role_name system.database_role_settings uses for defaults
// set with ALTER ROLE ALL.
const allRoles = ""

// roleDefaults returns the session variable defaults that apply in every
// database, by role name; allRoles holds those set for every role.
func roleDefaults(runtime *plugin.Runtime) (map[string]map[string]string, error) {
	v, err := crdbConnection(runtime).Memo("roleDefaults", func() (any, error) {
		rows, err := query(runtime, `SELECT role_name, settings FROM system.database_role_settings WHERE database_id = 0`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		defaults := map[string]map[string]string{}
		for rows.Next() {
			var role string
			var settings []string
			if err := rows.Scan(&role, &settings); err != nil {
				return nil, err
			}
			defaults[role] = parseSessionSettings(settings)
		}
		return defaults, rows.Err()
	})
	if err != nil {
		return nil, refused(err, "admin role (SELECT ON system.database_role_settings)")
	}
	return v.(map[string]map[string]string), nil
}

// parseSessionSettings parses "name=value" entries of
// system.database_role_settings.
func parseSessionSettings(settings []string) map[string]string {
	out := make(map[string]string, len(settings))
	for _, s := range settings {
		if k, v, ok := strings.Cut(s, "="); ok {
			out[k] = v
		}
	}
	return out
}

func (r *mqlCockroachdbRole) defaultSessionVariables() (map[string]any, error) {
	defaults, err := roleDefaults(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for k, v := range defaults[allRoles] {
		out[k] = v
	}
	for k, v := range defaults[r.Name.Data] {
		out[k] = v
	}
	return out, nil
}
