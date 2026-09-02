// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"database/sql"
	"fmt"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// hasPasswordExpr is the server-side projection behind the hasPassword field.
//
// mysql.user.authentication_string holds the account's credential (a password
// hash for the hashing plugins, empty otherwise). hasPassword only needs to
// know whether one is set, so the emptiness test is evaluated by the server and
// nothing but the resulting boolean crosses the connection. COALESCE keeps a
// NULL column reading as "no password", matching the pre-existing behavior.
//
// On MariaDB 10.4+ mysql.user is a view over mysql.global_priv whose
// authentication_string is itself a COALESCE expression, so it is never NULL
// and LENGTH over it behaves exactly as it does on MySQL.
func hasPasswordExpr(alias string) string {
	return fmt.Sprintf("LENGTH(COALESCE(%sauthentication_string, '')) > 0", alias)
}

// userColumns returns the mysql.user SELECT list for a flavor, with an optional
// table alias applied to each column (for joins).
func userColumns(alias string, mariadb bool) string {
	if mariadb {
		return fmt.Sprintf(`%[1]sUser, %[1]sHost, COALESCE(%[1]splugin, ''), %[2]s,
			COALESCE(%[1]sssl_type, ''), %[1]smax_connections, %[1]smax_user_connections,
			COALESCE(%[1]spassword_expired, 'N')`, alias, hasPasswordExpr(alias))
	}
	return fmt.Sprintf(`%[1]sUser, %[1]sHost, COALESCE(%[1]splugin, ''), %[2]s,
		COALESCE(%[1]sssl_type, ''), %[1]smax_connections, %[1]smax_user_connections,
		COALESCE(%[1]spassword_expired, 'N'), COALESCE(%[1]saccount_locked, 'N'),
		%[1]spassword_lifetime, %[1]spassword_last_changed`, alias, hasPasswordExpr(alias))
}

// hasPasswordValue maps the scanned hasPasswordExpr result to the field value.
// The comparison comes back as 1/0; a NULL (which COALESCE already rules out)
// reads as "no password" rather than becoming an error.
func hasPasswordValue(v sql.NullInt64) bool {
	return v.Valid && v.Int64 > 0
}

// buildMysqldbUser creates a user resource. Fields unavailable on the flavor are
// passed as nil/invalid and rendered as null.
func buildMysqldbUser(runtime *plugin.Runtime, serverID, user, host, authPlugin, sslType string, hasPassword bool,
	maxConn, maxUserConn int64, passwordExpired string,
	accountLocked *string, passwordLifetime sql.NullInt64, passwordLastChanged sql.NullTime) (*mqlMysqldbUser, error) {
	fields := map[string]*llx.RawData{
		"__id":               llx.StringData(userResourceID(serverID, user, host)),
		"user":               llx.StringData(user),
		"host":               llx.StringData(host),
		"authPlugin":         llx.StringData(authPlugin),
		"hasPassword":        llx.BoolData(hasPassword),
		"isAnonymous":        llx.BoolData(user == ""),
		"isWildcardHost":     llx.BoolData(host == "%"),
		"passwordExpired":    llx.BoolData(isYes(passwordExpired)),
		"sslType":            llx.StringData(sslType),
		"maxConnections":     llx.IntData(maxConn),
		"maxUserConnections": llx.IntData(maxUserConn),
	}
	if accountLocked != nil {
		fields["accountLocked"] = llx.BoolData(isYes(*accountLocked))
	} else {
		fields["accountLocked"] = llx.NilData
	}
	if passwordLifetime.Valid {
		fields["passwordLifetime"] = llx.IntData(passwordLifetime.Int64)
	} else {
		// NULL means "use the server default"; report -1 rather than unset.
		fields["passwordLifetime"] = llx.IntData(-1)
	}
	var lastChanged *time.Time
	if passwordLastChanged.Valid {
		lastChanged = &passwordLastChanged.Time
	}
	fields["passwordLastChanged"] = llx.TimeDataPtr(lastChanged)

	res, err := CreateResource(runtime, "mysqldb.user", fields)
	if err != nil {
		return nil, err
	}
	return res.(*mqlMysqldbUser), nil
}

func scanMysqldbUser(runtime *plugin.Runtime, serverID string, rows *sql.Rows, mariadb bool) (*mqlMysqldbUser, error) {
	var user, host, plugin, sslType, passwordExpired string
	var hasPassword sql.NullInt64
	var maxConn, maxUserConn int64
	if mariadb {
		if err := rows.Scan(&user, &host, &plugin, &hasPassword, &sslType, &maxConn, &maxUserConn, &passwordExpired); err != nil {
			return nil, err
		}
		return buildMysqldbUser(runtime, serverID, user, host, plugin, sslType, hasPasswordValue(hasPassword),
			maxConn, maxUserConn, passwordExpired, nil, sql.NullInt64{}, sql.NullTime{})
	}
	var accountLocked string
	var passwordLifetime sql.NullInt64
	var passwordLastChanged sql.NullTime
	if err := rows.Scan(&user, &host, &plugin, &hasPassword, &sslType, &maxConn, &maxUserConn,
		&passwordExpired, &accountLocked, &passwordLifetime, &passwordLastChanged); err != nil {
		return nil, err
	}
	return buildMysqldbUser(runtime, serverID, user, host, plugin, sslType, hasPasswordValue(hasPassword),
		maxConn, maxUserConn, passwordExpired, &accountLocked, passwordLifetime, passwordLastChanged)
}

func (r *mqlMysqldbInstance) users() ([]any, error) {
	db, err := mysqldbClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	serverID := r.__id
	mariadb := r.Flavor.Data == "mariadb"

	rows, err := db.QueryContext(mysqldbContext(), "SELECT "+userColumns("", mariadb)+" FROM mysql.user ORDER BY User, Host")
	if err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		u, err := scanMysqldbUser(r.MqlRuntime, serverID, rows, mariadb)
		if err != nil {
			return nil, err
		}
		list = append(list, u)
	}
	return list, rows.Err()
}

func (r *mqlMysqldbUser) grantedRoles() ([]any, error) {
	conn := mysqldbConnection(r.MqlRuntime)
	serverID, err := conn.ServerID()
	if err != nil {
		return nil, err
	}
	flavor, err := conn.Flavor()
	if err != nil {
		return nil, err
	}
	mariadb := flavor == "mariadb"
	db, err := conn.Client()
	if err != nil {
		return nil, err
	}

	var q string
	if mariadb {
		q = `SELECT ` + userColumns("u.", true) + `
			FROM mysql.roles_mapping rm
			JOIN mysql.user u ON rm.Role = u.User
			WHERE rm.User = ? AND rm.Host = ?`
	} else {
		q = `SELECT ` + userColumns("u.", false) + `
			FROM mysql.role_edges re
			JOIN mysql.user u ON re.FROM_USER = u.User AND re.FROM_HOST = u.Host
			WHERE re.TO_USER = ? AND re.TO_HOST = ?`
	}
	rows, err := db.QueryContext(mysqldbContext(), q, r.User.Data, r.Host.Data)
	if err != nil {
		// role tables require privilege or may not exist; treat as no roles.
		return []any{}, nil
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		u, err := scanMysqldbUser(r.MqlRuntime, serverID, rows, mariadb)
		if err != nil {
			return nil, err
		}
		list = append(list, u)
	}
	return list, rows.Err()
}

func (r *mqlMysqldbUser) privileges() ([]any, error) {
	return privilegesForGrantee(r.MqlRuntime, r.__id, grantee(r.User.Data, r.Host.Data))
}
