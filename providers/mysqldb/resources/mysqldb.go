// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	mysqldriver "github.com/go-sql-driver/mysql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mysqldb/connection"
)

func (r *mqlMysqldb) id() (string, error) {
	return "mysqldb", nil
}

func mysqldbConnection(runtime *plugin.Runtime) *connection.MysqldbConnection {
	return runtime.Connection.(*connection.MysqldbConnection)
}

func mysqldbClient(runtime *plugin.Runtime) (*sql.DB, error) {
	return mysqldbConnection(runtime).Client()
}

func mysqldbContext() context.Context {
	return context.Background()
}

// isAccessDenied reports whether an error is a MySQL access-denied error. Only
// these should be treated as "not visible"; other errors must propagate.
func isAccessDenied(err error) bool {
	var myErr *mysqldriver.MySQLError
	if !errors.As(err, &myErr) {
		return false
	}
	switch myErr.Number {
	case 1044, 1045, 1142, 1143, 1227, 1370: // db/table/column/routine access denied, no privilege
		return true
	default:
		return false
	}
}

// isMissingTable reports whether an error means the table or database does not
// exist (for example a catalog present on MySQL but not MariaDB).
func isMissingTable(err error) bool {
	var myErr *mysqldriver.MySQLError
	if !errors.As(err, &myErr) {
		return false
	}
	switch myErr.Number {
	case 1146, 1109, 1049: // no such table, unknown table, unknown database
		return true
	default:
		return false
	}
}

// grantee formats an account as the 'user'@'host' string information_schema uses.
func grantee(user, host string) string {
	return "'" + user + "'@'" + host + "'"
}

// --- stable identifier builders ---------------------------------------------

func userResourceID(serverID, user, host string) string {
	return serverID + "/user/" + user + "@" + host
}

func schemaResourceID(serverID, name string) string {
	return serverID + "/schema/" + name
}

func privilegeResourceID(parentID, scope, schema, table, privilegeType string) string {
	return parentID + "/priv/" + scope + "/" + schema + "/" + table + "/" + privilegeType
}

// --- privileges -------------------------------------------------------------

func newMysqldbPrivilege(runtime *plugin.Runtime, parentID, granteeStr, scope, schema, table, privilegeType string, grantable bool) (*mqlMysqldbPrivilege, error) {
	res, err := CreateResource(runtime, "mysqldb.privilege", map[string]*llx.RawData{
		"__id":          llx.StringData(privilegeResourceID(parentID, scope, schema, table, privilegeType)),
		"grantee":       llx.StringData(granteeStr),
		"scope":         llx.StringData(scope),
		"schema":        llx.StringData(schema),
		"table":         llx.StringData(table),
		"privilegeType": llx.StringData(privilegeType),
		"isGrantable":   llx.BoolData(grantable),
		// set by newObjectPrivilege for the scopes that have them
		"column":         llx.StringData(""),
		"routine":        llx.StringData(""),
		"routineType":    llx.StringData(""),
		"proxiedAccount": llx.StringData(""),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMysqldbPrivilege), nil
}

func isYes(s string) bool {
	return s == "YES" || s == "Y" || s == "ON" || s == "1"
}

// objectPrivilege is a privilege on a column, a stored routine, or another
// account (PROXY), which information_schema.USER_PRIVILEGES,
// SCHEMA_PRIVILEGES, and TABLE_PRIVILEGES do not list.
type objectPrivilege struct {
	scope, schema, table, column  string
	routine, routineType, proxied string
	privilegeType                 string
	grantable                     bool
}

// objectPrivilegeID keys an objectPrivilege under its account. The parts are
// joined with NUL, which cannot appear in a MySQL identifier, so a schema,
// table, or routine name containing '/' cannot collide with another row.
func objectPrivilegeID(parentID, granteeStr string, p objectPrivilege) string {
	return parentID + "/priv/" + strings.Join([]string{granteeStr, p.scope, p.schema, p.table,
		p.column, p.routineType, p.routine, p.proxied, p.privilegeType}, "\x00")
}

func newObjectPrivilege(runtime *plugin.Runtime, parentID, granteeStr string, p objectPrivilege) (*mqlMysqldbPrivilege, error) {
	res, err := CreateResource(runtime, "mysqldb.privilege", map[string]*llx.RawData{
		"__id":           llx.StringData(objectPrivilegeID(parentID, granteeStr, p)),
		"grantee":        llx.StringData(granteeStr),
		"scope":          llx.StringData(p.scope),
		"schema":         llx.StringData(p.schema),
		"table":          llx.StringData(p.table),
		"privilegeType":  llx.StringData(p.privilegeType),
		"isGrantable":    llx.BoolData(p.grantable),
		"column":         llx.StringData(p.column),
		"routine":        llx.StringData(p.routine),
		"routineType":    llx.StringData(p.routineType),
		"proxiedAccount": llx.StringData(p.proxied),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMysqldbPrivilege), nil
}

// routinePrivileges expands one mysql.procs_priv row. Proc_priv is a SET of
// Execute, Alter Routine, and Grant; Grant is the grant option on the others.
func routinePrivileges(schema, routine, routineType, procPriv string) []objectPrivilege {
	var types []string
	grantable := false
	for _, p := range strings.Split(procPriv, ",") {
		p = strings.TrimSpace(p)
		switch {
		case p == "":
		case strings.EqualFold(p, "Grant"):
			grantable = true
		default:
			types = append(types, strings.ToUpper(p))
		}
	}
	// GRANT ... ON PROCEDURE p TO u WITH GRANT OPTION followed by REVOKE
	// EXECUTE, ALTER ROUTINE leaves a row holding only Grant; the account can
	// still grant on the routine, which information_schema reports as the
	// GRANT OPTION privilege type at the other scopes.
	if len(types) == 0 && grantable {
		types = []string{"GRANT OPTION"}
	}
	res := make([]objectPrivilege, 0, len(types))
	for _, t := range types {
		res = append(res, objectPrivilege{
			scope: "ROUTINE", schema: schema, routine: routine, routineType: strings.ToUpper(routineType),
			privilegeType: t, grantable: grantable,
		})
	}
	return res
}
