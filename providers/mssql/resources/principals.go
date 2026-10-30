// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"database/sql"
	"fmt"

	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// initMssqlLogin resolves a single server login by name so typed references
// (for example mssql.databaseUser.login) return a fully populated login. Bulk
// listing goes through mssql.server.logins via CreateResource, which skips init.
func initMssqlLogin(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	nameRaw, ok := args["name"]
	if !ok {
		return args, nil, nil
	}
	name, _ := nameRaw.Value.(string)
	if name == "" {
		return nil, nil, fmt.Errorf("mssql.login requires a non-empty name")
	}

	client, err := mssqlClient(runtime)
	if err != nil {
		return nil, nil, err
	}
	q := `SELECT ` + loginColumns + `
		FROM sys.server_principals p
		LEFT JOIN sys.sql_logins sl ON p.principal_id = sl.principal_id
		WHERE p.name = @p1 AND p.type IN ('S','U','G','C','K')`
	rows, err := client.QueryContext(mssqlContext(), q, sql.Named("p1", name))
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("mssql.login %q not found", name)
	}
	res, err := scanLogin(runtime, rows)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// newMssqlLogin builds a login resource from a scanned server-principals row.
// The SID is canonicalized to S-1-5-... form for the exposed fields, and its
// binary form is cached for cross-database user matching.
func newMssqlLogin(runtime *plugin.Runtime, principalID int64, name, typeDesc, defaultDB string, sid []byte,
	createDate, modifyDate, passwordLastSet sql.NullTime, isDisabled, isFixedRole bool,
	isPolicyChecked, isExpirationChecked sql.NullBool, mustChange sql.NullInt64) (*mqlMssqlLogin, error) {
	instanceID := mssqlConnection(runtime).InstanceID()
	isAD := isActiveDirectoryType(typeDesc)
	canonicalSid := sidString(sid)

	fields := map[string]*llx.RawData{
		"__id":                       llx.StringData(serverPrincipalID(instanceID, name)),
		"name":                       llx.StringData(name),
		"principalId":                llx.IntData(principalID),
		"type":                       llx.StringData(typeDesc),
		"sid":                        llx.StringData(canonicalSid),
		"isDisabled":                 llx.BoolData(isDisabled),
		"isFixedRole":                llx.BoolData(isFixedRole),
		"defaultDatabase":            llx.StringData(defaultDB),
		"createDate":                 llx.TimeDataPtr(nullTime(createDate)),
		"modifyDate":                 llx.TimeDataPtr(nullTime(modifyDate)),
		"isActiveDirectoryPrincipal": llx.BoolData(isAD),
		"passwordLastSetTime":        llx.TimeDataPtr(nullTime(passwordLastSet)),
	}
	setLoginOptionalFields(fields, isAD, name, canonicalSid, isPolicyChecked, isExpirationChecked, mustChange)

	res, err := CreateResource(runtime, "mssql.login", fields)
	if err != nil {
		return nil, err
	}
	login := res.(*mqlMssqlLogin)
	login.cacheSid = sid
	return login, nil
}

// setActiveDirectoryFields sets the AD identity of a login or database user,
// or null for a principal that is not an Active Directory one. Every field is
// set either way, so none is left unset for the runtime to report as a
// provider bug.
func setActiveDirectoryFields(fields map[string]*llx.RawData, isAD bool, name, canonicalSid string) {
	if isAD {
		fields["activeDirectoryPrincipal"] = llx.StringData(name)
		fields["activeDirectorySid"] = llx.StringData(canonicalSid)
		return
	}
	fields["activeDirectoryPrincipal"] = llx.NilData
	fields["activeDirectorySid"] = llx.NilData
}

// setLoginOptionalFields sets the fields of a login that only some login types
// carry: the AD identity, and the password policy of a SQL login (NULL in
// sys.sql_logins for any other type), as null where they do not apply.
func setLoginOptionalFields(fields map[string]*llx.RawData, isAD bool, name, canonicalSid string,
	isPolicyChecked, isExpirationChecked sql.NullBool, mustChange sql.NullInt64) {
	setActiveDirectoryFields(fields, isAD, name, canonicalSid)
	fields["isPolicyChecked"] = llx.NilData
	if isPolicyChecked.Valid {
		fields["isPolicyChecked"] = llx.BoolData(isPolicyChecked.Bool)
	}
	fields["isExpirationChecked"] = llx.NilData
	if isExpirationChecked.Valid {
		fields["isExpirationChecked"] = llx.BoolData(isExpirationChecked.Bool)
	}
	fields["mustChange"] = llx.NilData
	if mustChange.Valid {
		fields["mustChange"] = llx.BoolData(mustChange.Int64 == 1)
	}
}

// roleColumns is the role column list shared by every query that builds a
// server or database role, so a role reached through membership is as complete
// as one from the listing; both share one cache entry.
const roleColumns = `r.principal_id, r.name, r.is_fixed_role, ISNULL(r.owning_principal_id, 0),
	r.create_date, r.modify_date`

// newMssqlServerRole builds a server-role resource from a row selected with
// roleColumns.
func newMssqlServerRole(runtime *plugin.Runtime, instanceID string, principalID int64, name string, isFixedRole bool,
	owningPid int64, createDate, modifyDate sql.NullTime) (*mqlMssqlServerRole, error) {
	res, err := CreateResource(runtime, "mssql.serverRole", map[string]*llx.RawData{
		"__id":              llx.StringData(serverPrincipalID(instanceID, name)),
		"name":              llx.StringData(name),
		"principalId":       llx.IntData(principalID),
		"isFixedRole":       llx.BoolData(isFixedRole),
		"owningPrincipalId": llx.IntData(owningPid),
		"createDate":        llx.TimeDataPtr(nullTime(createDate)),
		"modifyDate":        llx.TimeDataPtr(nullTime(modifyDate)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMssqlServerRole), nil
}

// newMssqlDatabaseRole builds a database-role resource from a row selected
// with roleColumns.
func newMssqlDatabaseRole(runtime *plugin.Runtime, database, dbID string, principalID int64, name string, isFixedRole bool,
	owningPid int64, createDate, modifyDate sql.NullTime) (*mqlMssqlDatabaseRole, error) {
	res, err := CreateResource(runtime, "mssql.databaseRole", map[string]*llx.RawData{
		"__id":              llx.StringData(databasePrincipalID(dbID, name)),
		"name":              llx.StringData(name),
		"principalId":       llx.IntData(principalID),
		"isFixedRole":       llx.BoolData(isFixedRole),
		"owningPrincipalId": llx.IntData(owningPid),
		"createDate":        llx.TimeDataPtr(nullTime(createDate)),
		"modifyDate":        llx.TimeDataPtr(nullTime(modifyDate)),
	})
	if err != nil {
		return nil, err
	}
	role := res.(*mqlMssqlDatabaseRole)
	role.cacheDatabase = database
	return role, nil
}

// --- mssql.login ------------------------------------------------------------

func (c *mqlMssqlLogin) explicitPermissions() ([]any, error) {
	if err := requireServerCatalog(c.MqlRuntime, "server permission"); err != nil {
		return nil, err
	}
	pid := c.PrincipalId.Data
	return serverPermissionsFor(c.MqlRuntime, c.__id, &pid)
}

func (c *mqlMssqlLogin) memberOfRoles() ([]any, error) {
	if err := requireServerCatalog(c.MqlRuntime, "server role membership"); err != nil {
		return nil, err
	}
	return serverRolesForMember(c.MqlRuntime, c.PrincipalId.Data)
}

func (c *mqlMssqlLogin) databaseUsers() ([]any, error) {
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if len(c.cacheSid) == 0 {
		return []any{}, nil
	}

	dbRows, err := client.QueryContext(mssqlContext(),
		"SELECT name FROM sys.databases WHERE state = 0")
	if err != nil {
		return nil, err
	}
	var dbNames []string
	for dbRows.Next() {
		var n string
		if err := dbRows.Scan(&n); err != nil {
			dbRows.Close()
			return nil, err
		}
		dbNames = append(dbNames, n)
	}
	dbRows.Close()
	if err := dbRows.Err(); err != nil {
		return nil, err
	}

	list := []any{}
	for _, dbName := range dbNames {
		// A database the scanner cannot read is a partition of a partial
		// result (ADR 046 §8): skip it and keep the others, and say so.
		if err := requireDatabaseCatalog(c.MqlRuntime, dbName, "database user"); err != nil {
			log.Warn().Err(err).Str("database", dbName).Str("login", c.Name.Data).Msg("mssql> skipping database for login.databaseUsers")
			continue
		}
		users, err := databaseUsersMatching(c.MqlRuntime, dbName, c.cacheSid)
		if err != nil {
			if isRefusal(err) || isDatabaseUnavailable(err) {
				log.Warn().Err(err).Str("database", dbName).Str("login", c.Name.Data).Msg("mssql> skipping database for login.databaseUsers")
				continue
			}
			return nil, err
		}
		list = append(list, users...)
	}
	return list, nil
}

// serverRolesForMember lists the server roles a principal is a direct member of.
func serverRolesForMember(runtime *plugin.Runtime, memberPrincipalID int64) ([]any, error) {
	client, err := mssqlClient(runtime)
	if err != nil {
		return nil, err
	}
	const q = `SELECT ` + roleColumns + `
		FROM sys.server_role_members rm
		JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
		WHERE rm.member_principal_id = @p1`
	rows, err := client.QueryContext(mssqlContext(), q, sql.Named("p1", memberPrincipalID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	instanceID := mssqlConnection(runtime).InstanceID()
	list := []any{}
	for rows.Next() {
		var pid, owningPid int64
		var name string
		var isFixedRole bool
		var createDate, modifyDate sql.NullTime
		if err := rows.Scan(&pid, &name, &isFixedRole, &owningPid, &createDate, &modifyDate); err != nil {
			return nil, err
		}
		role, err := newMssqlServerRole(runtime, instanceID, pid, name, isFixedRole, owningPid, createDate, modifyDate)
		if err != nil {
			return nil, err
		}
		list = append(list, role)
	}
	return list, rows.Err()
}

// --- mssql.serverRole -------------------------------------------------------

func (c *mqlMssqlServerRole) members() ([]any, error) {
	if err := requireServerCatalog(c.MqlRuntime, "server role member"); err != nil {
		return nil, err
	}
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	// Only login-type members are returned as mssql.login; nested role members
	// are reachable through each role's memberOfRoles.
	q := `SELECT ` + loginColumns + `
		FROM sys.server_role_members rm
		JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id
		LEFT JOIN sys.sql_logins sl ON p.principal_id = sl.principal_id
		WHERE rm.role_principal_id = @p1 AND p.type IN ('S','U','G','C','K')`
	rows, err := client.QueryContext(mssqlContext(), q, sql.Named("p1", c.PrincipalId.Data))
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

func (c *mqlMssqlServerRole) memberOfRoles() ([]any, error) {
	if err := requireServerCatalog(c.MqlRuntime, "server role membership"); err != nil {
		return nil, err
	}
	return serverRolesForMember(c.MqlRuntime, c.PrincipalId.Data)
}

func (c *mqlMssqlServerRole) explicitPermissions() ([]any, error) {
	if err := requireServerCatalog(c.MqlRuntime, "server permission"); err != nil {
		return nil, err
	}
	pid := c.PrincipalId.Data
	return serverPermissionsFor(c.MqlRuntime, c.__id, &pid)
}

// --- mssql.databaseUser -----------------------------------------------------

func (c *mqlMssqlDatabaseUser) login() (*mqlMssqlLogin, error) {
	if c.cacheLoginName == "" {
		c.Login.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(c.MqlRuntime, "mssql.login", map[string]*llx.RawData{
		"name": llx.StringData(c.cacheLoginName),
	})
	if err != nil {
		// A login the scanner cannot see is not an orphaned user.
		if err := requireServerCatalog(c.MqlRuntime, "login"); err != nil {
			return nil, err
		}
		// The mapped login is absent (orphaned user); treat as null.
		c.Login.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res.(*mqlMssqlLogin), nil
}

func (c *mqlMssqlDatabaseUser) explicitPermissions() ([]any, error) {
	if err := requireDatabaseCatalog(c.MqlRuntime, c.cacheDatabase, "database permission"); err != nil {
		return nil, err
	}
	pid := c.PrincipalId.Data
	return databasePermissionsFor(c.MqlRuntime, c.cacheDatabase, c.__id, &pid)
}

func (c *mqlMssqlDatabaseUser) memberOfRoles() ([]any, error) {
	if err := requireDatabaseCatalog(c.MqlRuntime, c.cacheDatabase, "database role membership"); err != nil {
		return nil, err
	}
	return databaseRolesForMember(c.MqlRuntime, c.cacheDatabase, c.PrincipalId.Data)
}

// --- mssql.databaseRole -----------------------------------------------------

func (c *mqlMssqlDatabaseRole) members() ([]any, error) {
	if err := requireDatabaseCatalog(c.MqlRuntime, c.cacheDatabase, "database role member"); err != nil {
		return nil, err
	}
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	db := quoteName(c.cacheDatabase)
	// Column order and types must match scanDatabaseUser (see dbUserColumns);
	// in particular sid is selected as raw binary, not a converted hex string.
	q := `SELECT m.principal_id, m.name, m.type_desc, ISNULL(m.authentication_type_desc, ''),
		ISNULL(m.default_schema_name, ''), m.sid,
		m.create_date, m.modify_date, ISNULL(SUSER_SNAME(m.sid), '')
		FROM ` + db + `.sys.database_role_members rm
		JOIN ` + db + `.sys.database_principals m ON rm.member_principal_id = m.principal_id
		WHERE rm.role_principal_id = @p1`
	rows, err := client.QueryContext(mssqlContext(), q, sql.Named("p1", c.PrincipalId.Data))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		u, err := scanDatabaseUser(c.MqlRuntime, c.cacheDatabase, rows)
		if err != nil {
			return nil, err
		}
		list = append(list, u)
	}
	return list, rows.Err()
}

func (c *mqlMssqlDatabaseRole) memberOfRoles() ([]any, error) {
	if err := requireDatabaseCatalog(c.MqlRuntime, c.cacheDatabase, "database role membership"); err != nil {
		return nil, err
	}
	return databaseRolesForMember(c.MqlRuntime, c.cacheDatabase, c.PrincipalId.Data)
}

func (c *mqlMssqlDatabaseRole) explicitPermissions() ([]any, error) {
	if err := requireDatabaseCatalog(c.MqlRuntime, c.cacheDatabase, "database permission"); err != nil {
		return nil, err
	}
	pid := c.PrincipalId.Data
	return databasePermissionsFor(c.MqlRuntime, c.cacheDatabase, c.__id, &pid)
}

// databaseRolesForMember lists the database roles a principal is a direct
// member of, within one database.
func databaseRolesForMember(runtime *plugin.Runtime, database string, memberPrincipalID int64) ([]any, error) {
	client, err := mssqlClient(runtime)
	if err != nil {
		return nil, err
	}
	db := quoteName(database)
	q := `SELECT ` + roleColumns + `
		FROM ` + db + `.sys.database_role_members rm
		JOIN ` + db + `.sys.database_principals r ON rm.role_principal_id = r.principal_id
		WHERE rm.member_principal_id = @p1`
	rows, err := client.QueryContext(mssqlContext(), q, sql.Named("p1", memberPrincipalID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	instanceID := mssqlConnection(runtime).InstanceID()
	dbID := databaseIdentifier(instanceID, database)
	list := []any{}
	for rows.Next() {
		var pid, owningPid int64
		var name string
		var isFixedRole bool
		var createDate, modifyDate sql.NullTime
		if err := rows.Scan(&pid, &name, &isFixedRole, &owningPid, &createDate, &modifyDate); err != nil {
			return nil, err
		}
		role, err := newMssqlDatabaseRole(runtime, database, dbID, pid, name, isFixedRole, owningPid, createDate, modifyDate)
		if err != nil {
			return nil, err
		}
		list = append(list, role)
	}
	return list, rows.Err()
}

// --- mssql.applicationRole --------------------------------------------------

func (c *mqlMssqlApplicationRole) explicitPermissions() ([]any, error) {
	if err := requireDatabaseCatalog(c.MqlRuntime, c.cacheDatabase, "database permission"); err != nil {
		return nil, err
	}
	pid := c.PrincipalId.Data
	return databasePermissionsFor(c.MqlRuntime, c.cacheDatabase, c.__id, &pid)
}

func (c *mqlMssqlApplicationRole) memberOfRoles() ([]any, error) {
	if err := requireDatabaseCatalog(c.MqlRuntime, c.cacheDatabase, "database role membership"); err != nil {
		return nil, err
	}
	return databaseRolesForMember(c.MqlRuntime, c.cacheDatabase, c.PrincipalId.Data)
}
