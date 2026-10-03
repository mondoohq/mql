// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"strconv"
	"strings"
)

// CallerAccess describes what the scanning account can see in
// information_schema. MySQL and MariaDB filter the privilege and catalog views
// by the caller's own privileges without raising an error, so a
// least-privileged scanner reads a partial answer that looks complete.
type CallerAccess struct {
	// Self is the scanning account as information_schema formats a grantee,
	// for example 'auditor'@'%'.
	Self string
	// GrantsVisible reports whether the information_schema privilege views
	// (USER_PRIVILEGES, SCHEMA_PRIVILEGES, TABLE_PRIVILEGES) list every
	// account. Without SELECT on the mysql schema they list the caller's own
	// rows only.
	GrantsVisible bool
	// Global holds the caller's own global privileges.
	Global map[string]bool
}

// CanListSchemas reports whether information_schema.SCHEMATA lists every
// schema: the caller holds SHOW DATABASES or SELECT globally. Otherwise only
// the schemas the caller holds a privilege on appear.
func (a *CallerAccess) CanListSchemas() bool {
	return a.Global["SHOW DATABASES"] || a.Global["SELECT"]
}

// CanListTables reports whether information_schema.TABLES lists every table:
// the caller holds SELECT globally. Otherwise only the tables the caller holds
// a privilege on appear.
func (a *CallerAccess) CanListTables() bool {
	return a.Global["SELECT"]
}

// CanListRoutines reports whether information_schema.ROUTINES lists every
// routine: the caller holds SELECT globally (which covers mysql.proc on MySQL
// 5.7 and MariaDB) or SHOW_ROUTINE (MySQL 8.0.20+). Otherwise only routines the
// caller defined or holds a routine privilege on appear.
func (a *CallerAccess) CanListRoutines() bool {
	return a.Global["SELECT"] || a.Global["SHOW_ROUTINE"]
}

// granteeString formats an account as the 'user'@'host' string
// information_schema uses for GRANTEE.
func granteeString(user, host string) string {
	return "'" + user + "'@'" + host + "'"
}

// parseCurrentUser splits the CURRENT_USER() value (user@host) into the
// grantee string. A user name may contain '@'; the host never does, so the
// split is at the last one.
func parseCurrentUser(s string) string {
	i := strings.LastIndex(s, "@")
	if i < 0 {
		return granteeString(s, "")
	}
	return granteeString(s[:i], s[i+1:])
}

// grantRow is one row of information_schema.USER_PRIVILEGES.
type grantRow struct {
	Grantee   string
	Privilege string
}

// newCallerAccess derives the caller's visibility from CURRENT_USER() and the
// rows of information_schema.USER_PRIVILEGES as the caller sees them. Every
// account has at least one row there (USAGE when it holds no global
// privilege), and the view filters to the caller's own rows unless it may read
// the mysql schema, so a second distinct grantee means the view is unfiltered.
// SCHEMA_PRIVILEGES and TABLE_PRIVILEGES use the same check.
func newCallerAccess(currentUser string, rows []grantRow) *CallerAccess {
	a := &CallerAccess{
		Self:   parseCurrentUser(currentUser),
		Global: map[string]bool{},
	}
	grantees := map[string]struct{}{}
	for _, row := range rows {
		grantees[row.Grantee] = struct{}{}
		if row.Grantee == a.Self {
			a.Global[strings.ToUpper(row.Privilege)] = true
		}
	}
	a.GrantsVisible = len(grantees) > 1
	return a
}

// CallerAccess reads what the scanning account may see. It runs once per
// connection.
func (c *MysqldbConnection) CallerAccess() (*CallerAccess, error) {
	c.accessOnce.Do(func() {
		c.access, c.accessErr = c.readCallerAccess()
	})
	return c.access, c.accessErr
}

func (c *MysqldbConnection) readCallerAccess() (*CallerAccess, error) {
	db, err := c.Client()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	var current string
	if err := db.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&current); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, "SELECT GRANTEE, PRIVILEGE_TYPE FROM information_schema.USER_PRIVILEGES")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []grantRow
	for rows.Next() {
		var row grantRow
		if err := rows.Scan(&row.Grantee, &row.Privilege); err != nil {
			return nil, err
		}
		list = append(list, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return newCallerAccess(current, list), nil
}

// HasRolesAndComponents reports whether the server has the MySQL 8.0 role
// (mysql.role_edges) and component (mysql.component) tables. MariaDB has
// neither component table nor role_edges, and MySQL before 8.0 has neither.
// The server answers a query on a table the caller holds no privilege on with
// access denied whether or not the table exists, so the absence has to be
// known from the version rather than read from the error.
func (c *MysqldbConnection) HasRolesAndComponents() (bool, error) {
	flavor, err := c.Flavor()
	if err != nil {
		return false, err
	}
	if flavor == "mariadb" {
		return false, nil
	}
	// resolveMeta, which Flavor ran, read @@version
	return majorVersion(c.version) >= 8, nil
}

// majorVersion returns the leading number of a server version such as
// 8.0.46-37 or 5.7.34-log, or 0 when there is none.
func majorVersion(v string) int {
	end := 0
	for end < len(v) && v[end] >= '0' && v[end] <= '9' {
		end++
	}
	n, _ := strconv.Atoi(v[:end])
	return n
}
