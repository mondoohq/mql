// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"database/sql"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// privilegesForGrantee lists the global, schema, and table privileges held by
// one account (grantee is the 'user'@'host' string).
func privilegesForGrantee(runtime *plugin.Runtime, parentID, granteeStr string) ([]any, error) {
	db, err := mysqldbClient(runtime)
	if err != nil {
		return nil, err
	}
	list := []any{}

	global, err := db.QueryContext(mysqldbContext(),
		`SELECT PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.USER_PRIVILEGES WHERE GRANTEE = ?`, granteeStr)
	if err != nil {
		return nil, err
	}
	for global.Next() {
		var priv, grantable string
		if err := global.Scan(&priv, &grantable); err != nil {
			global.Close()
			return nil, err
		}
		p, err := newMysqldbPrivilege(runtime, parentID, granteeStr, "GLOBAL", "", "", priv, isYes(grantable))
		if err != nil {
			global.Close()
			return nil, err
		}
		list = append(list, p)
	}
	global.Close()
	if err := global.Err(); err != nil {
		return nil, err
	}

	schema, err := db.QueryContext(mysqldbContext(),
		`SELECT TABLE_SCHEMA, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE = ?`, granteeStr)
	if err != nil {
		return nil, err
	}
	for schema.Next() {
		var sch, priv, grantable string
		if err := schema.Scan(&sch, &priv, &grantable); err != nil {
			schema.Close()
			return nil, err
		}
		p, err := newMysqldbPrivilege(runtime, parentID, granteeStr, "SCHEMA", sch, "", priv, isYes(grantable))
		if err != nil {
			schema.Close()
			return nil, err
		}
		list = append(list, p)
	}
	schema.Close()
	if err := schema.Err(); err != nil {
		return nil, err
	}

	table, err := db.QueryContext(mysqldbContext(),
		`SELECT TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.TABLE_PRIVILEGES WHERE GRANTEE = ?`, granteeStr)
	if err != nil {
		return nil, err
	}
	for table.Next() {
		var sch, tbl, priv, grantable string
		if err := table.Scan(&sch, &tbl, &priv, &grantable); err != nil {
			table.Close()
			return nil, err
		}
		p, err := newMysqldbPrivilege(runtime, parentID, granteeStr, "TABLE", sch, tbl, priv, isYes(grantable))
		if err != nil {
			table.Close()
			return nil, err
		}
		list = append(list, p)
	}
	table.Close()
	if err := table.Err(); err != nil {
		return nil, err
	}

	objects, err := objectPrivilegesForGrantee(db, granteeStr)
	if err != nil {
		return nil, err
	}
	for _, o := range objects {
		p, err := newObjectPrivilege(runtime, parentID, granteeStr, o)
		if err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	return list, nil
}

// granteeMatch selects mysql.* grant table rows for a 'user'@'host' grantee,
// formatting the row the way information_schema formats GRANTEE.
const granteeMatch = "CONCAT('''', User, '''@''', Host, '''') = ?"

// objectPrivilegesForGrantee lists one account's column, routine, and proxy
// privileges. Routine and proxy grants exist only in mysql.procs_priv and
// mysql.proxies_priv; a caller that cannot read them gets no rows unless
// StructuredErrors is on, where the refusal is an error.
func objectPrivilegesForGrantee(db *sql.DB, granteeStr string) ([]objectPrivilege, error) {
	var res []objectPrivilege

	cols, err := db.QueryContext(mysqldbContext(),
		`SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, PRIVILEGE_TYPE, IS_GRANTABLE
		 FROM information_schema.COLUMN_PRIVILEGES WHERE GRANTEE = ?`, granteeStr)
	if err != nil {
		return nil, err
	}
	for cols.Next() {
		var o objectPrivilege
		var grantable string
		if err := cols.Scan(&o.schema, &o.table, &o.column, &o.privilegeType, &grantable); err != nil {
			cols.Close()
			return nil, err
		}
		o.scope = "COLUMN"
		o.grantable = isYes(grantable)
		res = append(res, o)
	}
	cols.Close()
	if err := cols.Err(); err != nil {
		return nil, err
	}

	routines, err := db.QueryContext(mysqldbContext(),
		`SELECT Db, Routine_name, Routine_type, Proc_priv FROM mysql.procs_priv WHERE `+granteeMatch, granteeStr)
	if err != nil {
		if !isAccessDenied(err) {
			return nil, err
		}
		if plugin.StructuredErrors() {
			return nil, llx.Forbidden(err, llx.WithPermissions("SELECT ON mysql.procs_priv"))
		}
		// v13 listed no routine grants: skip them and still read the
		// proxy grants below
	} else {
		for routines.Next() {
			var schema, name, typ, procPriv string
			if err := routines.Scan(&schema, &name, &typ, &procPriv); err != nil {
				routines.Close()
				return nil, err
			}
			res = append(res, routinePrivileges(schema, name, typ, procPriv)...)
		}
		routines.Close()
		if err := routines.Err(); err != nil {
			return nil, err
		}
	}

	proxies, err := db.QueryContext(mysqldbContext(),
		`SELECT Proxied_user, Proxied_host, With_grant FROM mysql.proxies_priv WHERE `+granteeMatch, granteeStr)
	if err != nil {
		if !isAccessDenied(err) {
			return nil, err
		}
		if plugin.StructuredErrors() {
			return nil, llx.Forbidden(err, llx.WithPermissions("SELECT ON mysql.proxies_priv"))
		}
		return res, nil
	}
	defer proxies.Close()
	for proxies.Next() {
		var user, host string
		var withGrant int64
		if err := proxies.Scan(&user, &host, &withGrant); err != nil {
			return nil, err
		}
		res = append(res, objectPrivilege{
			scope: "PROXY", proxied: grantee(user, host), privilegeType: "PROXY", grantable: withGrant != 0,
		})
	}
	return res, proxies.Err()
}

// scanScopedPrivileges runs a privilege query returning
// (grantee, privilege_type, is_grantable) and builds privileges at one scope.
func scanScopedPrivileges(runtime *plugin.Runtime, parentID, scope, schema, tableName string, rows *sql.Rows) ([]any, error) {
	list := []any{}
	for rows.Next() {
		var granteeStr, priv, grantable string
		if err := rows.Scan(&granteeStr, &priv, &grantable); err != nil {
			return nil, err
		}
		p, err := newMysqldbPrivilege(runtime, parentID, granteeStr, scope, schema, tableName, priv, isYes(grantable))
		if err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	return list, rows.Err()
}

// privilegesForSchema lists the privileges granted on a schema (any grantee).
func privilegesForSchema(runtime *plugin.Runtime, parentID, schema string) ([]any, error) {
	db, err := mysqldbClient(runtime)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(mysqldbContext(),
		`SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA = ?`, schema)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanScopedPrivileges(runtime, parentID, "SCHEMA", schema, "", rows)
}

// privilegesForTable lists the privileges granted on a table (any grantee).
func privilegesForTable(runtime *plugin.Runtime, parentID, schema, tableName string) ([]any, error) {
	db, err := mysqldbClient(runtime)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(mysqldbContext(),
		`SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.TABLE_PRIVILEGES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?`, schema, tableName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanScopedPrivileges(runtime, parentID, "TABLE", schema, tableName, rows)
}
