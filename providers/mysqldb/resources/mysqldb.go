// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

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

// refusedList is what a list accessor returns when the server refused its
// query. v13 returned an empty list, which let a check over the list pass on a
// server the scanner could not read; with StructuredErrors the refusal is an
// error naming the privilege the scanner lacks (ADR 046).
func refusedList(err error, permissions ...string) ([]any, error) {
	if !plugin.StructuredErrors() {
		return []any{}, nil
	}
	return nil, llx.Forbidden(err, llx.WithPermissions(permissions...))
}

// requireVisibility guards a read from an information_schema view that the
// server filters by the caller's privileges without raising an error. When
// the caller would see only part of the view, the read is refused instead of
// returning the partial list as if it were complete. v13 returned the partial
// list, so the check only runs with StructuredErrors.
func requireVisibility(runtime *plugin.Runtime, visible func(*connection.CallerAccess) bool, what string, permissions ...string) error {
	if !plugin.StructuredErrors() {
		return nil
	}
	access, err := mysqldbConnection(runtime).CallerAccess()
	if err != nil {
		return err
	}
	if visible(access) {
		return nil
	}
	return llx.Forbidden(
		fmt.Errorf("%s cannot see every %s: information_schema lists only the rows it holds privileges on", access.Self, what),
		llx.WithPermissions(permissions...))
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
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMysqldbPrivilege), nil
}

func isYes(s string) bool {
	return s == "YES" || s == "Y" || s == "ON" || s == "1"
}
