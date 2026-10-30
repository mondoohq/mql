// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"database/sql"
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// loginColumns is the server-principal column list used to build a full
// mssql.login. Keep it in sync with the scan order in scanLogin.
const loginColumns = `p.principal_id, p.name, p.type_desc, p.is_disabled, p.is_fixed_role,
	p.create_date, p.modify_date, ISNULL(p.default_database_name, ''),
	p.sid,
	sl.is_policy_checked, sl.is_expiration_checked,
	CONVERT(INT, LOGINPROPERTY(p.name, 'IsMustChange')),
	CONVERT(DATETIME, LOGINPROPERTY(p.name, 'PasswordLastSetTime'))`

// scanLogin builds an mssql.login from a row selected with loginColumns.
func scanLogin(runtime *plugin.Runtime, rows *sql.Rows) (*mqlMssqlLogin, error) {
	var principalID int64
	var name, typeDesc, defaultDB string
	var sid []byte
	var createDate, modifyDate, passwordLastSet sql.NullTime
	var isDisabled, isFixedRole bool
	var isPolicyChecked, isExpirationChecked sql.NullBool
	var mustChange sql.NullInt64
	if err := rows.Scan(&principalID, &name, &typeDesc, &isDisabled, &isFixedRole,
		&createDate, &modifyDate, &defaultDB, &sid,
		&isPolicyChecked, &isExpirationChecked, &mustChange, &passwordLastSet); err != nil {
		return nil, err
	}
	return newMssqlLogin(runtime, principalID, name, typeDesc, defaultDB, sid,
		createDate, modifyDate, passwordLastSet, isDisabled, isFixedRole,
		isPolicyChecked, isExpirationChecked, mustChange)
}

// --- mssql.credential -------------------------------------------------------

func (c *mqlMssqlCredential) mappedLogins() ([]any, error) {
	if err := requireServerCatalog(c.MqlRuntime, "credential mapping"); err != nil {
		return nil, err
	}
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	q := `SELECT ` + loginColumns + `
		FROM sys.server_principal_credentials pc
		JOIN sys.credentials cr ON pc.credential_id = cr.credential_id
		JOIN sys.server_principals p ON pc.principal_id = p.principal_id
		LEFT JOIN sys.sql_logins sl ON p.principal_id = sl.principal_id
		WHERE cr.name = @p1`
	rows, err := client.QueryContext(mssqlContext(), q, sql.Named("p1", c.Name.Data))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		login, err := scanLogin(c.MqlRuntime, rows)
		if err != nil {
			return nil, err
		}
		list = append(list, login)
	}
	return list, rows.Err()
}

// --- mssql.proxyAccount -----------------------------------------------------

func (c *mqlMssqlProxyAccount) authorizedLogins() ([]any, error) {
	if err := requireServerCatalog(c.MqlRuntime, "login"); err != nil {
		return nil, err
	}
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	q := `SELECT ` + loginColumns + `
		FROM msdb.dbo.sysproxylogin pl
		JOIN msdb.dbo.sysproxies pr ON pl.proxy_id = pr.proxy_id
		JOIN sys.server_principals p ON pl.sid = p.sid
		LEFT JOIN sys.sql_logins sl ON p.principal_id = sl.principal_id
		WHERE pr.name = @p1`
	rows, err := client.QueryContext(mssqlContext(), q, sql.Named("p1", c.Name.Data))
	if err != nil {
		// msdb proxy tables require explicit access; a refusal is not "no
		// authorized logins".
		return refusedList(err, "SELECT ON msdb.dbo.sysproxylogin")
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		login, err := scanLogin(c.MqlRuntime, rows)
		if err != nil {
			return nil, err
		}
		list = append(list, login)
	}
	return list, rows.Err()
}

// --- mssql.linkedServer -----------------------------------------------------

func (c *mqlMssqlLinkedServer) linkedLogins() ([]any, error) {
	if err := requireServerCatalog(c.MqlRuntime, "linked login"); err != nil {
		return nil, err
	}
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	const q = `SELECT ISNULL(sp.name, ''), ISNULL(ll.remote_name, ''), ll.uses_self_credential
		FROM sys.linked_logins ll
		JOIN sys.servers s ON ll.server_id = s.server_id
		LEFT JOIN sys.server_principals sp ON ll.local_principal_id = sp.principal_id
		WHERE s.name = @p1`
	rows, err := client.QueryContext(mssqlContext(), q, sql.Named("p1", c.Name.Data))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	idx := 0
	for rows.Next() {
		var localLogin, remoteName string
		var usesSelf bool
		if err := rows.Scan(&localLogin, &remoteName, &usesSelf); err != nil {
			return nil, err
		}
		res, err := CreateResource(c.MqlRuntime, "mssql.linkedServer.login", map[string]*llx.RawData{
			"__id":               llx.StringData(fmt.Sprintf("%s/login/%d", c.__id, idx)),
			"localLogin":         llx.StringData(localLogin),
			"remoteName":         llx.StringData(remoteName),
			"usesSelfCredential": llx.BoolData(usesSelf),
		})
		if err != nil {
			return nil, err
		}
		idx++
		list = append(list, res)
	}
	return list, rows.Err()
}
