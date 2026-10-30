// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// relkindDesc maps a pg_class.relkind code to a readable relation kind.
func relkindDesc(code string) string {
	switch code {
	case "r":
		return "table"
	case "v":
		return "view"
	case "m":
		return "materializedView"
	case "f":
		return "foreignTable"
	case "p":
		return "partitionedTable"
	default:
		return code
	}
}

// policyCommandDesc maps a pg_policy.polcmd code to the statement type it covers.
func policyCommandDesc(code string) string {
	switch code {
	case "*":
		return "ALL"
	case "r":
		return "SELECT"
	case "a":
		return "INSERT"
	case "w":
		return "UPDATE"
	case "d":
		return "DELETE"
	default:
		return code
	}
}

func (r *mqlPostgresdbSchema) tables() ([]any, error) {
	pool, err := pgPool(r.MqlRuntime, r.cacheDatabase)
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(pgContext(),
		`SELECT c.relname, c.oid::bigint, c.relkind, COALESCE(o.rolname, ''),
			`+pgColumn(r.MqlRuntime, pgVersion95, "c.relrowsecurity", "false")+`,
			`+pgColumn(r.MqlRuntime, pgVersion95, "c.relforcerowsecurity", "false")+`
		 FROM pg_class c
		 JOIN pg_namespace n ON c.relnamespace = n.oid
		 LEFT JOIN pg_roles o ON c.relowner = o.oid
		 WHERE n.nspname = $1 AND c.relkind IN ('r', 'v', 'm', 'f', 'p')
		 ORDER BY c.relname`, r.Name.Data)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, relkind, ownerName string
		var oid int64
		var rlsEnabled, rlsForced bool
		if err := rows.Scan(&name, &oid, &relkind, &ownerName, &rlsEnabled, &rlsForced); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "postgresdb.table", map[string]*llx.RawData{
			"__id":               llx.StringData(r.__id + "/table/" + name),
			"name":               llx.StringData(name),
			"oid":                llx.IntData(oid),
			"schema":             llx.StringData(r.Name.Data),
			"kind":               llx.StringData(relkindDesc(relkind)),
			"rowSecurityEnabled": llx.BoolData(rlsEnabled),
			"rowSecurityForced":  llx.BoolData(rlsForced),
		})
		if err != nil {
			return nil, err
		}
		tbl := res.(*mqlPostgresdbTable)
		tbl.cacheDatabase = r.cacheDatabase
		tbl.cacheOwner = ownerName
		list = append(list, tbl)
	}
	return list, rows.Err()
}

func (r *mqlPostgresdbTable) owner() (*mqlPostgresdbRole, error) {
	return resolveRoleRef(r.MqlRuntime, r.cacheOwner, &r.Owner)
}

func (r *mqlPostgresdbTable) privileges() ([]any, error) {
	pool, err := pgPool(r.MqlRuntime, r.cacheDatabase)
	if err != nil {
		return nil, err
	}
	return aclPrivileges(r.MqlRuntime, pool, r.__id,
		`SELECT COALESCE(gr.rolname, 'PUBLIC'), a.privilege_type, a.is_grantable
		 FROM pg_class c, aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
		 LEFT JOIN pg_roles gr ON gr.oid = a.grantee
		 WHERE c.oid = $1::oid`, r.Oid.Data)
}

func (r *mqlPostgresdbTable) policies() ([]any, error) {
	// Row-level security arrived in 9.5; an older server has no policies.
	if !pgAtLeast(r.MqlRuntime, pgVersion95) {
		return []any{}, nil
	}
	pool, err := pgPool(r.MqlRuntime, r.cacheDatabase)
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(pgContext(),
		`SELECT pol.polname, pol.polcmd, `+pgColumn(r.MqlRuntime, pgVersion10, "pol.polpermissive", "true")+`,
			COALESCE((SELECT array_agg(CASE WHEN x = 0 THEN 'PUBLIC'
				ELSE (SELECT rolname FROM pg_roles WHERE oid = x) END)
				FROM unnest(pol.polroles) AS x), '{}'),
			COALESCE(pg_get_expr(pol.polqual, pol.polrelid), ''),
			COALESCE(pg_get_expr(pol.polwithcheck, pol.polrelid), '')
		 FROM pg_policy pol WHERE pol.polrelid = $1::oid ORDER BY pol.polname`, r.Oid.Data)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, cmd, usingExpr, checkExpr string
		var permissive bool
		var roles []string
		if err := rows.Scan(&name, &cmd, &permissive, &roles, &usingExpr, &checkExpr); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "postgresdb.rlsPolicy", map[string]*llx.RawData{
			"__id":            llx.StringData(r.__id + "/policy/" + name),
			"name":            llx.StringData(name),
			"command":         llx.StringData(policyCommandDesc(cmd)),
			"permissive":      llx.BoolData(permissive),
			"roles":           llx.ArrayData(strSliceToAny(roles), types.String),
			"usingExpression": llx.StringData(usingExpr),
			"checkExpression": llx.StringData(checkExpr),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}
