// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"database/sql"
	"errors"

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

// privilegeResourceID keys a privilege row. The grantee is part of the key
// because schema and table privileges list every account under one parent.
func privilegeResourceID(parentID, granteeStr, scope, schema, table, privilegeType string) string {
	return parentID + "/priv/" + granteeStr + "/" + scope + "/" + schema + "/" + table + "/" + privilegeType
}

// pluginResourceID keys a plugin row. The type is part of the key because one
// name can be registered under several plugin types (MariaDB's uuid is both a
// DATA TYPE and a FUNCTION).
func pluginResourceID(serverID, name, pluginType string) string {
	return serverID + "/plugin/" + pluginType + "/" + name
}

// --- privileges -------------------------------------------------------------

func newMysqldbPrivilege(runtime *plugin.Runtime, parentID, granteeStr, scope, schema, table, privilegeType string, grantable bool) (*mqlMysqldbPrivilege, error) {
	res, err := CreateResource(runtime, "mysqldb.privilege", map[string]*llx.RawData{
		"__id":          llx.StringData(privilegeResourceID(parentID, granteeStr, scope, schema, table, privilegeType)),
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
