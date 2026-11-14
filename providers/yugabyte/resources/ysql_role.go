// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ysqlRoleRow is one role from pg_roles, which every user can read.
type ysqlRoleRow struct {
	name          string
	isSuperuser   bool
	canLogin      bool
	canCreateRole bool
	canCreateDb   bool
	bypassRls     bool
	memberOf      []string
}

// ysqlRoleRows lists every role once per connection, with its direct
// memberships from pg_auth_members.
func ysqlRoleRows(runtime *plugin.Runtime) ([]ysqlRoleRow, error) {
	v, err := ybConnection(runtime).Memo("ysqlRoles", func() (any, error) {
		rows, err := ysqlQuery(runtime, `SELECT r.rolname, r.rolsuper, r.rolcanlogin, r.rolcreaterole, r.rolcreatedb, r.rolbypassrls,
			COALESCE(ARRAY(SELECT g.rolname FROM pg_catalog.pg_auth_members m
				JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
				WHERE m.member = r.oid ORDER BY g.rolname), ARRAY[]::text[])
			FROM pg_catalog.pg_roles r ORDER BY r.rolname`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		list := []ysqlRoleRow{}
		for rows.Next() {
			var row ysqlRoleRow
			if err := rows.Scan(&row.name, &row.isSuperuser, &row.canLogin, &row.canCreateRole,
				&row.canCreateDb, &row.bypassRls, &row.memberOf); err != nil {
				return nil, err
			}
			list = append(list, row)
		}
		return list, rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return v.([]ysqlRoleRow), nil
}

func ysqlRoleArgs(row ysqlRoleRow) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":          llx.StringData("yugabyte.ysql.role/" + row.name),
		"name":          llx.StringData(row.name),
		"isSuperuser":   llx.BoolData(row.isSuperuser),
		"canLogin":      llx.BoolData(row.canLogin),
		"canCreateRole": llx.BoolData(row.canCreateRole),
		"canCreateDb":   llx.BoolData(row.canCreateDb),
		"bypassRls":     llx.BoolData(row.bypassRls),
	}
}

func (r *mqlYugabyteYsqlRole) id() (string, error) {
	return "yugabyte.ysql.role/" + r.Name.Data, nil
}

// initYugabyteYsqlRole resolves a role by name, for typed references such
// as an owner or a member.
func initYugabyteYsqlRole(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	raw, ok := args["name"]
	if !ok {
		return nil, nil, fmt.Errorf("yugabyte.ysql.role needs a name")
	}
	name, _ := raw.Value.(string)
	rows, err := ysqlRoleRows(runtime)
	if err != nil {
		return nil, nil, err
	}
	for _, row := range rows {
		if row.name == name {
			return ysqlRoleArgs(row), nil, nil
		}
	}
	return nil, nil, fmt.Errorf("yugabyte.ysql.role %q not found", name)
}

func (r *mqlYugabyteYsql) roles() ([]any, error) {
	rows, err := ysqlRoleRows(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := make([]any, 0, len(rows))
	for _, row := range rows {
		res, err := CreateResource(r.MqlRuntime, "yugabyte.ysql.role", ysqlRoleArgs(row))
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlYugabyteYsqlRole) memberOf() ([]any, error) {
	rows, err := ysqlRoleRows(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, row := range rows {
		if row.name == r.Name.Data {
			names = row.memberOf
			break
		}
	}
	list := make([]any, 0, len(names))
	for _, name := range names {
		res, err := NewResource(r.MqlRuntime, "yugabyte.ysql.role", map[string]*llx.RawData{
			"name": llx.StringData(name),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

// resolveRole resolves a role by name for an owner or grantee reference. A
// name that is no role, such as PUBLIC, resolves to null.
func resolveRole(runtime *plugin.Runtime, name string, field *plugin.TValue[*mqlYugabyteYsqlRole]) (*mqlYugabyteYsqlRole, error) {
	rows, err := ysqlRoleRows(runtime)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if row.name == name {
			res, err := NewResource(runtime, "yugabyte.ysql.role", map[string]*llx.RawData{
				"name": llx.StringData(name),
			})
			if err != nil {
				return nil, err
			}
			return res.(*mqlYugabyteYsqlRole), nil
		}
	}
	field.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// ysqlPasswordState is what the provider keeps of a role's password: whether
// it has one and whether it is the role's name. The hash is dropped as soon
// as it is checked.
type ysqlPasswordState struct {
	hasPassword bool
	equalsName  bool
}

// ysqlPasswords checks every role's stored password once per connection.
// pg_authid is readable only by superusers.
func ysqlPasswords(runtime *plugin.Runtime) (map[string]ysqlPasswordState, error) {
	v, err := ybConnection(runtime).Memo("ysqlPasswords", func() (any, error) {
		rows, err := ysqlQuery(runtime, `SELECT rolname, COALESCE(rolpassword, '') FROM pg_catalog.pg_authid`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := map[string]ysqlPasswordState{}
		for rows.Next() {
			var name, hash string
			if err := rows.Scan(&name, &hash); err != nil {
				return nil, err
			}
			out[name] = ysqlPasswordState{
				hasPassword: hash != "",
				equalsName:  hash != "" && ysqlPasswordMatches(hash, name, name),
			}
		}
		return out, rows.Err()
	})
	if err != nil {
		return nil, refused(err, "superuser (SELECT ON pg_authid)")
	}
	return v.(map[string]ysqlPasswordState), nil
}

func (r *mqlYugabyteYsqlRole) passwordState() (ysqlPasswordState, error) {
	states, err := ysqlPasswords(r.MqlRuntime)
	if err != nil {
		return ysqlPasswordState{}, err
	}
	state, ok := states[r.Name.Data]
	if !ok {
		return ysqlPasswordState{}, fmt.Errorf("yugabyte.ysql.role %q not found in pg_authid", r.Name.Data)
	}
	return state, nil
}

func (r *mqlYugabyteYsqlRole) hasPassword() (bool, error) {
	state, err := r.passwordState()
	return state.hasPassword, err
}

func (r *mqlYugabyteYsqlRole) passwordEqualsName() (bool, error) {
	state, err := r.passwordState()
	return state.equalsName, err
}
