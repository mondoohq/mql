// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/mysqldb/connection"
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

// legacyHasPasswordExpr is hasPasswordExpr for MariaDB before 10.4, where an
// account using the default authentication keeps its hash in the Password
// column and leaves plugin and authentication_string empty.
func legacyHasPasswordExpr(alias string) string {
	return fmt.Sprintf("LENGTH(COALESCE(NULLIF(%[1]sauthentication_string, ''), %[1]sPassword, '')) > 0", alias)
}

// legacyAuthPluginExpr reports the plugin MariaDB before 10.4 authenticates an
// account with: an empty plugin column means the built-in password
// authentication, mysql_old_password for a 16-character pre-4.1 hash and
// mysql_native_password otherwise. A role does not authenticate and keeps the
// empty plugin.
func legacyAuthPluginExpr(alias string) string {
	return fmt.Sprintf(`CASE WHEN COALESCE(%[1]splugin, '') <> '' THEN %[1]splugin
			WHEN COALESCE(%[1]sis_role, 'N') = 'Y' THEN ''
			WHEN LENGTH(COALESCE(%[1]sPassword, '')) = 16 THEN 'mysql_old_password'
			ELSE 'mysql_native_password' END`, alias)
}

// userSchema selects the mysql.user layout to read.
type userSchema int

const (
	// MySQL and Percona: the lock and lifetime columns live in mysql.user.
	userSchemaMySQL userSchema = iota
	// MariaDB 10.4+: mysql.user is a view over mysql.global_priv, whose Priv
	// JSON holds account_locked, password_lifetime and password_last_changed.
	userSchemaMariaDB
	// MariaDB 10.4+ when the caller cannot read mysql.global_priv: the lock
	// and lifetime fields are unknown.
	userSchemaMariaDBNoGlobalPriv
	// MariaDB before 10.4: mysql.user is a table with a Password column and no
	// account locking or password lifetime.
	userSchemaMariaDBLegacy
)

// mariadbUserSchema picks the layout for a MariaDB version string.
func mariadbUserSchema(version string) userSchema {
	major, minor := majorMinor(version)
	if major > 10 || (major == 10 && minor >= 4) {
		return userSchemaMariaDB
	}
	return userSchemaMariaDBLegacy
}

// majorMinor returns the first two numbers of a version such as
// 10.3.39-MariaDB-0ubuntu0.20.04.2.
// It is only given @@version of a server already identified as MariaDB,
// which always starts with digits; anything else reads as 0.0.
func majorMinor(v string) (int, int) {
	var nums [2]int
	i := 0
	for n := 0; n < 2; n++ {
		start := i
		for i < len(v) && v[i] >= '0' && v[i] <= '9' {
			i++
		}
		nums[n], _ = strconv.Atoi(v[start:i])
		if i >= len(v) || v[i] != '.' {
			break
		}
		i++
	}
	return nums[0], nums[1]
}

// globalPrivJoin joins mysql.global_priv (alias gp) to mysql.user aliased u.
const globalPrivJoin = ` LEFT JOIN mysql.global_priv gp ON gp.User = u.User AND gp.Host = u.Host`

// userFrom returns the FROM clause reading accounts for a layout, with
// mysql.user aliased u.
func userFrom(schema userSchema) string {
	if schema == userSchemaMariaDB {
		return "mysql.user u" + globalPrivJoin
	}
	return "mysql.user u"
}

// userColumns returns the SELECT list for a layout. alias is applied to the
// mysql.user columns; the MariaDB 10.4+ layout also reads gp
// (mysql.global_priv, see userFrom).
func userColumns(alias string, schema userSchema) string {
	switch schema {
	case userSchemaMariaDB, userSchemaMariaDBNoGlobalPriv:
		locked, lifetime, changed := "NULL", "NULL", "NULL"
		if schema == userSchemaMariaDB {
			locked = "JSON_VALUE(gp.Priv, '$.account_locked')"
			lifetime = "JSON_VALUE(gp.Priv, '$.password_lifetime')"
			changed = "JSON_VALUE(gp.Priv, '$.password_last_changed')"
		}
		return fmt.Sprintf(`%[1]sUser, %[1]sHost, COALESCE(%[1]splugin, ''), %[2]s,
			COALESCE(%[1]sssl_type, ''), %[1]smax_connections, %[1]smax_user_connections,
			COALESCE(%[1]spassword_expired, 'N'), %[3]s, %[4]s, %[5]s,
			COALESCE(%[1]sis_role, 'N')`, alias, hasPasswordExpr(alias), locked, lifetime, changed)
	case userSchemaMariaDBLegacy:
		return fmt.Sprintf(`%[1]sUser, %[1]sHost, %[2]s, %[3]s,
			COALESCE(%[1]sssl_type, ''), %[1]smax_connections, %[1]smax_user_connections,
			COALESCE(%[1]spassword_expired, 'N'), COALESCE(%[1]sis_role, 'N')`,
			alias, legacyAuthPluginExpr(alias), legacyHasPasswordExpr(alias))
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

// mysqldbUserRow is one account as read from mysql.user. Fields a layout does
// not have stay nil or invalid and are rendered as null.
type mysqldbUserRow struct {
	user, host, authPlugin, sslType string
	hasPassword                     bool
	maxConn, maxUserConn            int64
	passwordExpired                 string
	accountLocked                   *bool
	passwordLifetime                sql.NullInt64
	passwordLastChanged             *time.Time
	isRole                          *bool
}

// mariadbGlobalPriv decodes the mysql.global_priv Priv JSON values read with
// JSON_VALUE, which renders the JSON true of account_locked as 1. An absent
// account_locked means unlocked. An absent or -1
// password_lifetime means the server default. password_last_changed is epoch
// seconds; MariaDB writes 0 to mark a password expired (and for accounts that
// never had one), which is not a time the password was changed.
func mariadbGlobalPriv(locked, lifetime, lastChanged sql.NullString) (*bool, sql.NullInt64, *time.Time) {
	isLocked := locked.Valid && (locked.String == "1" || strings.EqualFold(locked.String, "true"))
	life := sql.NullInt64{}
	if lifetime.Valid {
		if n, err := strconv.ParseInt(lifetime.String, 10, 64); err == nil && n >= 0 {
			life = sql.NullInt64{Int64: n, Valid: true}
		}
	}
	var changed *time.Time
	if lastChanged.Valid {
		if n, err := strconv.ParseInt(lastChanged.String, 10, 64); err == nil && n > 0 {
			t := time.Unix(n, 0).UTC()
			changed = &t
		}
	}
	return &isLocked, life, changed
}

// buildMysqldbUser creates a user resource.
func buildMysqldbUser(runtime *plugin.Runtime, serverID string, row mysqldbUserRow) (*mqlMysqldbUser, error) {
	fields := map[string]*llx.RawData{
		"__id":                llx.StringData(userResourceID(serverID, row.user, row.host)),
		"user":                llx.StringData(row.user),
		"host":                llx.StringData(row.host),
		"authPlugin":          llx.StringData(row.authPlugin),
		"hasPassword":         llx.BoolData(row.hasPassword),
		"isAnonymous":         llx.BoolData(row.user == ""),
		"isWildcardHost":      llx.BoolData(row.host == "%"),
		"passwordExpired":     llx.BoolData(isYes(row.passwordExpired)),
		"sslType":             llx.StringData(row.sslType),
		"maxConnections":      llx.IntData(row.maxConn),
		"maxUserConnections":  llx.IntData(row.maxUserConn),
		"accountLocked":       llx.BoolDataPtr(row.accountLocked),
		"passwordLastChanged": llx.TimeDataPtr(row.passwordLastChanged),
		"isRole":              llx.BoolDataPtr(row.isRole),
	}
	if row.passwordLifetime.Valid {
		fields["passwordLifetime"] = llx.IntData(row.passwordLifetime.Int64)
	} else {
		// NULL means "use the server default"; report -1 rather than unset.
		fields["passwordLifetime"] = llx.IntData(-1)
	}

	res, err := CreateResource(runtime, "mysqldb.user", fields)
	if err != nil {
		return nil, err
	}
	return res.(*mqlMysqldbUser), nil
}

func scanMysqldbUser(runtime *plugin.Runtime, serverID string, rows *sql.Rows, schema userSchema) (*mqlMysqldbUser, error) {
	var row mysqldbUserRow
	var hasPassword sql.NullInt64
	switch schema {
	case userSchemaMariaDB, userSchemaMariaDBNoGlobalPriv:
		var locked, lifetime, lastChanged sql.NullString
		var isRole string
		if err := rows.Scan(&row.user, &row.host, &row.authPlugin, &hasPassword, &row.sslType, &row.maxConn, &row.maxUserConn,
			&row.passwordExpired, &locked, &lifetime, &lastChanged, &isRole); err != nil {
			return nil, err
		}
		if schema == userSchemaMariaDB {
			row.accountLocked, row.passwordLifetime, row.passwordLastChanged = mariadbGlobalPriv(locked, lifetime, lastChanged)
		}
		role := isYes(isRole)
		row.isRole = &role
	case userSchemaMariaDBLegacy:
		var isRole string
		if err := rows.Scan(&row.user, &row.host, &row.authPlugin, &hasPassword, &row.sslType, &row.maxConn, &row.maxUserConn,
			&row.passwordExpired, &isRole); err != nil {
			return nil, err
		}
		role := isYes(isRole)
		row.isRole = &role
	default:
		var accountLocked string
		var passwordLastChanged sql.NullTime
		if err := rows.Scan(&row.user, &row.host, &row.authPlugin, &hasPassword, &row.sslType, &row.maxConn, &row.maxUserConn,
			&row.passwordExpired, &accountLocked, &row.passwordLifetime, &passwordLastChanged); err != nil {
			return nil, err
		}
		locked := isYes(accountLocked)
		row.accountLocked = &locked
		if passwordLastChanged.Valid {
			row.passwordLastChanged = &passwordLastChanged.Time
		}
	}
	row.hasPassword = hasPasswordValue(hasPassword)
	return buildMysqldbUser(runtime, serverID, row)
}

// userSchemaFor picks the mysql.user layout for the connected server.
func userSchemaFor(conn *connection.MysqldbConnection) (userSchema, error) {
	flavor, err := conn.Flavor()
	if err != nil {
		return 0, err
	}
	if flavor != "mariadb" {
		return userSchemaMySQL, nil
	}
	version, err := conn.Version()
	if err != nil {
		return 0, err
	}
	return mariadbUserSchema(version), nil
}

// queryUsers runs a query over mysql.user built by build. On MariaDB 10.4+ a
// caller that may read mysql.user but not mysql.global_priv gets the accounts
// without the lock and lifetime fields rather than no accounts.
func queryUsers(conn *connection.MysqldbConnection, build func(userSchema) string, args ...any) (*sql.Rows, userSchema, error) {
	schema, err := userSchemaFor(conn)
	if err != nil {
		return nil, 0, err
	}
	db, err := conn.Client()
	if err != nil {
		return nil, 0, err
	}
	rows, err := db.QueryContext(mysqldbContext(), build(schema), args...)
	if err != nil && schema == userSchemaMariaDB && isAccessDenied(err) {
		schema = userSchemaMariaDBNoGlobalPriv
		rows, err = db.QueryContext(mysqldbContext(), build(schema), args...)
	}
	return rows, schema, err
}

func (r *mqlMysqldbInstance) users() ([]any, error) {
	conn := mysqldbConnection(r.MqlRuntime)
	serverID := r.__id

	rows, schema, err := queryUsers(conn, func(schema userSchema) string {
		return "SELECT " + userColumns("u.", schema) + " FROM " + userFrom(schema) + " ORDER BY u.User, u.Host"
	})
	if err != nil {
		if isAccessDenied(err) {
			return refusedList(err, "SELECT ON mysql.user")
		}
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		u, err := scanMysqldbUser(r.MqlRuntime, serverID, rows, schema)
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
	// MySQL before 8.0 has no roles; MariaDB keeps them in roles_mapping
	if hasRoles, err := conn.HasRolesAndComponents(); err != nil {
		return nil, err
	} else if !mariadb && !hasRoles {
		return []any{}, nil
	}
	roleTable := "mysql.role_edges"
	if mariadb {
		roleTable = "mysql.roles_mapping"
	}

	rows, schema, err := queryUsers(conn, func(schema userSchema) string {
		if schema == userSchemaMySQL {
			return `SELECT ` + userColumns("u.", schema) + `
			FROM mysql.role_edges re
			JOIN mysql.user u ON re.FROM_USER = u.User AND re.FROM_HOST = u.Host
			WHERE re.TO_USER = ? AND re.TO_HOST = ?`
		}
		from := " JOIN mysql.user u ON rm.Role = u.User AND u.Host = ''"
		if schema == userSchemaMariaDB {
			from += globalPrivJoin
		}
		return `SELECT ` + userColumns("u.", schema) + `
			FROM mysql.roles_mapping rm` + from + `
			WHERE rm.User = ? AND rm.Host = ?`
	}, r.User.Data, r.Host.Data)
	if err != nil {
		// MySQL 5.7 has no role_edges table: no roles exist there.
		if isMissingTable(err) {
			return []any{}, nil
		}
		if isAccessDenied(err) {
			return refusedList(err, "SELECT ON "+roleTable, "SELECT ON mysql.user")
		}
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		u, err := scanMysqldbUser(r.MqlRuntime, serverID, rows, schema)
		if err != nil {
			return nil, err
		}
		list = append(list, u)
	}
	return list, rows.Err()
}

func (r *mqlMysqldbUser) privileges() ([]any, error) {
	g := grantee(r.User.Data, r.Host.Data)
	// information_schema always shows the caller its own grants
	if err := requireVisibility(r.MqlRuntime, func(a *connection.CallerAccess) bool {
		return a.GrantsVisible || a.Self == g
	}, "account's privileges", "SELECT ON mysql.*"); err != nil {
		return nil, err
	}
	return privilegesForGrantee(r.MqlRuntime, r.__id, g)
}
