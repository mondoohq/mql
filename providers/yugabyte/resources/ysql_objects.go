// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// systemSchemas filters out the schemas YSQL itself owns.
const systemSchemas = `n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp\_%'`

// relationKinds maps pg_class.relkind to the kind the table resource
// reports. Indexes and composite types are not relations a privilege
// matters on and are left out.
var relationKinds = map[string]string{
	"r": "table",
	"p": "partitioned table",
	"v": "view",
	"m": "materialized view",
	"f": "foreign table",
	"S": "sequence",
}

func relationKind(relkind string) string {
	if k, ok := relationKinds[relkind]; ok {
		return k
	}
	return relkind
}

type mqlYugabyteYsqlTableInternal struct {
	ownerName string
}

func (r *mqlYugabyteYsql) tables() ([]any, error) {
	rows, err := ysqlQuery(r.MqlRuntime, `SELECT n.nspname, c.relname, c.relkind::text, pg_catalog.pg_get_userbyid(c.relowner),
		c.relrowsecurity, c.relforcerowsecurity
		FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') AND `+systemSchemas+`
		ORDER BY n.nspname, c.relname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []any{}
	for rows.Next() {
		var schema, name, kind, owner string
		var rls, forceRls bool
		if err := rows.Scan(&schema, &name, &kind, &owner, &rls, &forceRls); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "yugabyte.ysql.table", map[string]*llx.RawData{
			"__id":             llx.StringData("yugabyte.ysql.table/" + schema + "." + name),
			"name":             llx.StringData(name),
			"schema":           llx.StringData(schema),
			"kind":             llx.StringData(relationKind(kind)),
			"rowSecurity":      llx.BoolData(rls),
			"forceRowSecurity": llx.BoolData(forceRls),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlYugabyteYsqlTable).ownerName = owner
		list = append(list, res)
	}
	return list, rows.Err()
}

func (r *mqlYugabyteYsqlTable) owner() (*mqlYugabyteYsqlRole, error) {
	return resolveRole(r.MqlRuntime, r.ownerName, &r.Owner)
}

func (r *mqlYugabyteYsqlTable) grants() ([]any, error) {
	all, err := ysqlGrantRows(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := []any{}
	for _, g := range all {
		if g.schema == r.Schema.Data && g.object == r.Name.Data {
			res, err := createGrant(r.MqlRuntime, g)
			if err != nil {
				return nil, err
			}
			list = append(list, res)
		}
	}
	return list, nil
}

// grantRow is one privilege on a relation, from aclexplode over
// pg_class.relacl, which every user can read. An unset ACL stands for the
// default privileges, which acldefault spells out.
type grantRow struct {
	grantee     string
	privilege   string
	objectType  string
	schema      string
	object      string
	isGrantable bool
}

func ysqlGrantRows(runtime *plugin.Runtime) ([]grantRow, error) {
	v, err := ybConnection(runtime).Memo("ysqlGrants", func() (any, error) {
		// The same privilege granted by two grantors is one grant here; it
		// is grantable when either grant is.
		rows, err := ysqlQuery(runtime, `SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS grantee,
			a.privilege_type, c.relkind::text, n.nspname, c.relname, bool_or(a.is_grantable)
			FROM pg_catalog.pg_class c
			JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace,
			LATERAL aclexplode(COALESCE(c.relacl, acldefault(CASE WHEN c.relkind = 'S' THEN 's' ELSE 'r' END::"char", c.relowner))) a
			WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S') AND `+systemSchemas+`
			GROUP BY 1, 2, 3, 4, 5
			ORDER BY 4, 5, 1, 2`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		list := []grantRow{}
		for rows.Next() {
			var g grantRow
			var kind string
			if err := rows.Scan(&g.grantee, &g.privilege, &kind, &g.schema, &g.object, &g.isGrantable); err != nil {
				return nil, err
			}
			g.objectType = relationKind(kind)
			list = append(list, g)
		}
		return list, rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return v.([]grantRow), nil
}

func createGrant(runtime *plugin.Runtime, g grantRow) (plugin.Resource, error) {
	return CreateResource(runtime, "yugabyte.ysql.grant", map[string]*llx.RawData{
		"__id":        llx.StringData("yugabyte.ysql.grant/" + g.schema + "." + g.object + "/" + g.grantee + "/" + g.privilege),
		"grantee":     llx.StringData(g.grantee),
		"privilege":   llx.StringData(g.privilege),
		"objectType":  llx.StringData(g.objectType),
		"schema":      llx.StringData(g.schema),
		"object":      llx.StringData(g.object),
		"isGrantable": llx.BoolData(g.isGrantable),
	})
}

func (r *mqlYugabyteYsql) grants() ([]any, error) {
	all, err := ysqlGrantRows(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	list := make([]any, 0, len(all))
	for _, g := range all {
		res, err := createGrant(r.MqlRuntime, g)
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlYugabyteYsqlGrant) role() (*mqlYugabyteYsqlRole, error) {
	if r.Grantee.Data == "PUBLIC" {
		r.Role.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveRole(r.MqlRuntime, r.Grantee.Data, &r.Role)
}

type mqlYugabyteYsqlFunctionInternal struct {
	ownerName string
}

func (r *mqlYugabyteYsql) functions() ([]any, error) {
	rows, err := ysqlQuery(r.MqlRuntime, `SELECT n.nspname, p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid),
		l.lanname, p.prosecdef, COALESCE(p.proconfig, ARRAY[]::text[]), pg_catalog.pg_get_userbyid(p.proowner)
		FROM pg_catalog.pg_proc p
		JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
		JOIN pg_catalog.pg_language l ON l.oid = p.prolang
		WHERE `+systemSchemas+`
		ORDER BY n.nspname, p.proname, 3`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []any{}
	for rows.Next() {
		var schema, name, arguments, language, owner string
		var secdef bool
		var config []string
		if err := rows.Scan(&schema, &name, &arguments, &language, &secdef, &config, &owner); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "yugabyte.ysql.function", map[string]*llx.RawData{
			"__id":            llx.StringData("yugabyte.ysql.function/" + schema + "." + name + "(" + arguments + ")"),
			"name":            llx.StringData(name),
			"schema":          llx.StringData(schema),
			"arguments":       llx.StringData(arguments),
			"language":        llx.StringData(language),
			"securityDefiner": llx.BoolData(secdef),
			"configuration":   llx.ArrayData(toAnySlice(config), types.String),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlYugabyteYsqlFunction).ownerName = owner
		list = append(list, res)
	}
	return list, rows.Err()
}

func (r *mqlYugabyteYsqlFunction) owner() (*mqlYugabyteYsqlRole, error) {
	return resolveRole(r.MqlRuntime, r.ownerName, &r.Owner)
}
