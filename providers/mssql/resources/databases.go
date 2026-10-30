// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"database/sql"
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// dbUserColumns is the canonical database-principal column list shared by every
// query that builds an mssql.databaseUser, so scanDatabaseUser can read them.
const dbUserColumns = `p.principal_id, p.name, p.type_desc, ISNULL(p.authentication_type_desc, ''),
	ISNULL(p.default_schema_name, ''), p.sid,
	p.create_date, p.modify_date, ISNULL(SUSER_SNAME(p.sid), '')`

// initMssqlDatabase resolves a database by name, defaulting to the connection's
// scoped database so a bare mssql.database can serve as a database asset root.
func initMssqlDatabase(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := mssqlConnection(runtime)
	if _, ok := args["name"]; !ok && conn.Database() != "" {
		args["name"] = llx.StringData(conn.Database())
	}
	nameRaw, ok := args["name"]
	if !ok {
		return args, nil, nil
	}
	name, _ := nameRaw.Value.(string)
	if name == "" {
		return nil, nil, fmt.Errorf("mssql.database requires a non-empty name")
	}

	client, err := conn.Client()
	if err != nil {
		return nil, nil, err
	}
	const q = `SELECT d.database_id, d.name,
		d.owner_sid, ISNULL(SUSER_SNAME(d.owner_sid), ''),
		(SELECT sp.principal_id FROM sys.server_principals sp WHERE sp.sid = d.owner_sid),
		d.create_date, d.compatibility_level, ISNULL(d.collation_name, ''),
		d.is_read_only, d.is_trustworthy_on, d.is_encrypted, d.is_auto_close_on,
		d.containment_desc, d.state_desc, d.is_broker_enabled
		FROM sys.databases d WHERE d.name = @p1`

	var databaseID, compatLevel int64
	var dbName, ownerName, collation, containment, stateDesc string
	var ownerSid []byte
	var ownerPrincipalID sql.NullInt64
	var createDate sql.NullTime
	var isReadOnly, isTrustworthy, isEncrypted, isAutoClose, isBroker bool
	err = client.QueryRowContext(mssqlContext(), q, sql.Named("p1", name)).Scan(
		&databaseID, &dbName, &ownerSid, &ownerName, &ownerPrincipalID, &createDate, &compatLevel, &collation,
		&isReadOnly, &isTrustworthy, &isEncrypted, &isAutoClose, &containment, &stateDesc, &isBroker)
	if err == sql.ErrNoRows {
		return nil, nil, fmt.Errorf("mssql.database %q not found", name)
	}
	if err != nil {
		return nil, nil, err
	}

	instanceID := conn.InstanceID()
	res, err := CreateResource(runtime, "mssql.database", map[string]*llx.RawData{
		"__id":               llx.StringData(databaseIdentifier(instanceID, dbName)),
		"name":               llx.StringData(dbName),
		"databaseId":         llx.IntData(databaseID),
		"ownerName":          llx.StringData(ownerName),
		"ownerSid":           llx.StringData(sidString(ownerSid)),
		"ownerPrincipalId":   nullInt(ownerPrincipalID),
		"createDate":         llx.TimeDataPtr(nullTime(createDate)),
		"compatibilityLevel": llx.IntData(compatLevel),
		"collation":          llx.StringData(collation),
		"isReadOnly":         llx.BoolData(isReadOnly),
		"isTrustworthy":      llx.BoolData(isTrustworthy),
		"isEncrypted":        llx.BoolData(isEncrypted),
		"isAutoCloseOn":      llx.BoolData(isAutoClose),
		"containment":        llx.StringData(containment),
		"stateDesc":          llx.StringData(stateDesc),
		"isBrokerEnabled":    llx.BoolData(isBroker),
	})
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// scanDatabaseUser builds an mssql.databaseUser from a row selected with
// dbUserColumns.
func scanDatabaseUser(runtime *plugin.Runtime, database string, rows *sql.Rows) (*mqlMssqlDatabaseUser, error) {
	var principalID int64
	var name, typeDesc, authType, defaultSchema, loginName string
	var sid []byte
	var createDate, modifyDate sql.NullTime
	if err := rows.Scan(&principalID, &name, &typeDesc, &authType, &defaultSchema, &sid,
		&createDate, &modifyDate, &loginName); err != nil {
		return nil, err
	}

	instanceID := mssqlConnection(runtime).InstanceID()
	dbID := databaseIdentifier(instanceID, database)
	isAD := isActiveDirectoryType(typeDesc)
	canonicalSid := sidString(sid)
	fields := map[string]*llx.RawData{
		"__id":                       llx.StringData(databasePrincipalID(dbID, name)),
		"name":                       llx.StringData(name),
		"principalId":                llx.IntData(principalID),
		"type":                       llx.StringData(typeDesc),
		"authenticationType":         llx.StringData(authType),
		"defaultSchema":              llx.StringData(defaultSchema),
		"sid":                        llx.StringData(canonicalSid),
		"isActiveDirectoryPrincipal": llx.BoolData(isAD),
		"createDate":                 llx.TimeDataPtr(nullTime(createDate)),
		"modifyDate":                 llx.TimeDataPtr(nullTime(modifyDate)),
	}
	setActiveDirectoryFields(fields, isAD, name, canonicalSid)
	res, err := CreateResource(runtime, "mssql.databaseUser", fields)
	if err != nil {
		return nil, err
	}
	user := res.(*mqlMssqlDatabaseUser)
	user.cacheDatabase = database
	user.cacheLoginName = loginName
	return user, nil
}

// databaseUsersMatching returns the users in a database whose SID matches the
// given hex SID, used to map a login to its database users.
func databaseUsersMatching(runtime *plugin.Runtime, database string, sidBinary []byte) ([]any, error) {
	client, err := mssqlClient(runtime)
	if err != nil {
		return nil, err
	}
	db := quoteName(database)
	q := `SELECT ` + dbUserColumns + `
		FROM ` + db + `.sys.database_principals p
		WHERE p.type IN ('S','U','G','C','K','E','X')
		AND p.sid = @p1`
	rows, err := client.QueryContext(mssqlContext(), q, sql.Named("p1", sidBinary))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		u, err := scanDatabaseUser(runtime, database, rows)
		if err != nil {
			return nil, err
		}
		list = append(list, u)
	}
	return list, rows.Err()
}

// --- mssql.database collections ---------------------------------------------

func (c *mqlMssqlDatabase) users() ([]any, error) {
	if err := requireDatabaseCatalog(c.MqlRuntime, c.Name.Data, "database user"); err != nil {
		return nil, err
	}
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	db := quoteName(c.Name.Data)
	q := `SELECT ` + dbUserColumns + `
		FROM ` + db + `.sys.database_principals p
		WHERE p.type IN ('S','U','G','C','K','E','X')
		ORDER BY p.principal_id`
	rows, err := client.QueryContext(mssqlContext(), q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		u, err := scanDatabaseUser(c.MqlRuntime, c.Name.Data, rows)
		if err != nil {
			return nil, err
		}
		list = append(list, u)
	}
	return list, rows.Err()
}

func (c *mqlMssqlDatabase) roles() ([]any, error) {
	if err := requireDatabaseCatalog(c.MqlRuntime, c.Name.Data, "database role"); err != nil {
		return nil, err
	}
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	db := quoteName(c.Name.Data)
	q := `SELECT principal_id, name, is_fixed_role, ISNULL(owning_principal_id, 0),
		create_date, modify_date
		FROM ` + db + `.sys.database_principals
		WHERE type = 'R' ORDER BY principal_id`
	rows, err := client.QueryContext(mssqlContext(), q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	instanceID := mssqlConnection(c.MqlRuntime).InstanceID()
	dbID := databaseIdentifier(instanceID, c.Name.Data)
	list := []any{}
	for rows.Next() {
		var pid, owningPid int64
		var name string
		var isFixedRole bool
		var createDate, modifyDate sql.NullTime
		if err := rows.Scan(&pid, &name, &isFixedRole, &owningPid, &createDate, &modifyDate); err != nil {
			return nil, err
		}
		role, err := newMssqlDatabaseRole(c.MqlRuntime, c.Name.Data, dbID, pid, name, isFixedRole, owningPid, createDate, modifyDate)
		if err != nil {
			return nil, err
		}
		list = append(list, role)
	}
	return list, rows.Err()
}

func (c *mqlMssqlDatabase) applicationRoles() ([]any, error) {
	if err := requireDatabaseCatalog(c.MqlRuntime, c.Name.Data, "application role"); err != nil {
		return nil, err
	}
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	db := quoteName(c.Name.Data)
	q := `SELECT principal_id, name, ISNULL(default_schema_name, ''), ISNULL(owning_principal_id, 0),
		create_date, modify_date
		FROM ` + db + `.sys.database_principals
		WHERE type = 'A' ORDER BY principal_id`
	rows, err := client.QueryContext(mssqlContext(), q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	instanceID := mssqlConnection(c.MqlRuntime).InstanceID()
	dbID := databaseIdentifier(instanceID, c.Name.Data)
	list := []any{}
	for rows.Next() {
		var pid, owningPid int64
		var name, defaultSchema string
		var createDate, modifyDate sql.NullTime
		if err := rows.Scan(&pid, &name, &defaultSchema, &owningPid, &createDate, &modifyDate); err != nil {
			return nil, err
		}
		res, err := CreateResource(c.MqlRuntime, "mssql.applicationRole", map[string]*llx.RawData{
			"__id":              llx.StringData(databasePrincipalID(dbID, name)),
			"name":              llx.StringData(name),
			"principalId":       llx.IntData(pid),
			"owningPrincipalId": llx.IntData(owningPid),
			"defaultSchema":     llx.StringData(defaultSchema),
			"createDate":        llx.TimeDataPtr(nullTime(createDate)),
			"modifyDate":        llx.TimeDataPtr(nullTime(modifyDate)),
		})
		if err != nil {
			return nil, err
		}
		appRole := res.(*mqlMssqlApplicationRole)
		appRole.cacheDatabase = c.Name.Data
		list = append(list, appRole)
	}
	return list, rows.Err()
}

func (c *mqlMssqlDatabase) permissions() ([]any, error) {
	if err := requireDatabaseCatalog(c.MqlRuntime, c.Name.Data, "database permission"); err != nil {
		return nil, err
	}
	return databasePermissionsFor(c.MqlRuntime, c.Name.Data, c.__id, nil)
}

func (c *mqlMssqlDatabase) scopedCredentials() ([]any, error) {
	if err := requireDatabaseCatalog(c.MqlRuntime, c.Name.Data, "database scoped credential"); err != nil {
		return nil, err
	}
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	db := quoteName(c.Name.Data)
	q := `SELECT name, ISNULL(credential_identity, ''), create_date, modify_date
		FROM ` + db + `.sys.database_scoped_credentials ORDER BY credential_id`
	rows, err := client.QueryContext(mssqlContext(), q)
	if err != nil {
		// The catalog view is absent before SQL Server 2016, which is no
		// credentials; a refusal is not.
		return refusedList(err, "VIEW DEFINITION ON DATABASE::"+db)
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, identity string
		var createDate, modifyDate sql.NullTime
		if err := rows.Scan(&name, &identity, &createDate, &modifyDate); err != nil {
			return nil, err
		}
		res, err := CreateResource(c.MqlRuntime, "mssql.databaseScopedCredential", map[string]*llx.RawData{
			"__id":       llx.StringData(c.__id + "/scopedCredential/" + name),
			"name":       llx.StringData(name),
			"identity":   llx.StringData(identity),
			"createDate": llx.TimeDataPtr(nullTime(createDate)),
			"modifyDate": llx.TimeDataPtr(nullTime(modifyDate)),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (c *mqlMssqlDatabase) symmetricKeys() ([]any, error) {
	if err := requireDatabaseCatalog(c.MqlRuntime, c.Name.Data, "symmetric key"); err != nil {
		return nil, err
	}
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	db := quoteName(c.Name.Data)
	q := `SELECT name, ISNULL(algorithm_desc, ''), ISNULL(key_length, 0), create_date
		FROM ` + db + `.sys.symmetric_keys`
	rows, err := client.QueryContext(mssqlContext(), q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, algorithm string
		var keyLength int64
		var createDate sql.NullTime
		if err := rows.Scan(&name, &algorithm, &keyLength, &createDate); err != nil {
			return nil, err
		}
		res, err := CreateResource(c.MqlRuntime, "mssql.symmetricKey", map[string]*llx.RawData{
			"__id":       llx.StringData(c.__id + "/symkey/" + name),
			"name":       llx.StringData(name),
			"algorithm":  llx.StringData(algorithm),
			"keyLength":  llx.IntData(keyLength),
			"createDate": llx.TimeDataPtr(nullTime(createDate)),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (c *mqlMssqlDatabase) asymmetricKeys() ([]any, error) {
	if err := requireDatabaseCatalog(c.MqlRuntime, c.Name.Data, "asymmetric key"); err != nil {
		return nil, err
	}
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	db := quoteName(c.Name.Data)
	q := `SELECT name, ISNULL(algorithm_desc, ''), ISNULL(key_length, 0)
		FROM ` + db + `.sys.asymmetric_keys`
	rows, err := client.QueryContext(mssqlContext(), q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, algorithm string
		var keyLength int64
		if err := rows.Scan(&name, &algorithm, &keyLength); err != nil {
			return nil, err
		}
		res, err := CreateResource(c.MqlRuntime, "mssql.asymmetricKey", map[string]*llx.RawData{
			"__id":      llx.StringData(c.__id + "/asymkey/" + name),
			"name":      llx.StringData(name),
			"algorithm": llx.StringData(algorithm),
			"keyLength": llx.IntData(keyLength),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (c *mqlMssqlDatabase) clrAssemblies() ([]any, error) {
	if err := requireDatabaseDefinitions(c.MqlRuntime, c.Name.Data, "assembly"); err != nil {
		return nil, err
	}
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	db := quoteName(c.Name.Data)
	q := `SELECT name, ISNULL(permission_set_desc, ''), is_user_defined
		FROM ` + db + `.sys.assemblies`
	rows, err := client.QueryContext(mssqlContext(), q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, permissionSet string
		var isUserDefined bool
		if err := rows.Scan(&name, &permissionSet, &isUserDefined); err != nil {
			return nil, err
		}
		res, err := CreateResource(c.MqlRuntime, "mssql.clrAssembly", map[string]*llx.RawData{
			"__id":          llx.StringData(c.__id + "/assembly/" + name),
			"name":          llx.StringData(name),
			"permissionSet": llx.StringData(permissionSet),
			"isUserDefined": llx.BoolData(isUserDefined),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (c *mqlMssqlDatabase) auditSpecifications() ([]any, error) {
	if err := requireDatabaseCatalog(c.MqlRuntime, c.Name.Data, "database audit specification"); err != nil {
		return nil, err
	}
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	db := quoteName(c.Name.Data)

	details := map[int64]map[string]any{}
	actions := map[int64][]any{}
	detailRows, err := client.QueryContext(mssqlContext(),
		`SELECT d.database_specification_id, d.audit_action_name, ISNULL(d.audited_result, ''),
			d.class_desc, d.is_group,
			ISNULL(CASE d.class
				WHEN 0 THEN @p1
				WHEN 1 THEN os.name + '.' + o.name
				WHEN 3 THEN s.name
			END, ''),
			ISNULL(pr.name, '')
		 FROM `+db+`.sys.database_audit_specification_details d
		 LEFT JOIN `+db+`.sys.all_objects o ON d.class = 1 AND d.major_id = o.object_id
		 LEFT JOIN `+db+`.sys.schemas os ON o.schema_id = os.schema_id
		 LEFT JOIN `+db+`.sys.schemas s ON d.class = 3 AND d.major_id = s.schema_id
		 LEFT JOIN `+db+`.sys.database_principals pr ON d.audited_principal_id = pr.principal_id
		 ORDER BY d.database_specification_id, d.audit_action_name, d.class, d.major_id, d.minor_id`,
		sql.Named("p1", c.Name.Data))
	if err == nil {
		for detailRows.Next() {
			var specID int64
			var action, result, class, securable, principal string
			var isGroup bool
			if err := detailRows.Scan(&specID, &action, &result, &class, &isGroup, &securable, &principal); err != nil {
				detailRows.Close()
				return nil, err
			}
			if details[specID] == nil {
				details[specID] = map[string]any{}
			}
			// actionGroups is keyed by action name, so an action audited on
			// several objects keeps one entry (the last row's result);
			// auditedActions carries one entry per row.
			details[specID][action] = result
			actions[specID] = append(actions[specID], auditedAction(action, class, securable, principal, isGroup))
		}
		err = detailRows.Err()
		detailRows.Close()
		if err != nil {
			return nil, err
		}
	}

	q := `SELECT s.database_specification_id, s.name, s.is_state_enabled, ISNULL(a.name, '')
		FROM ` + db + `.sys.database_audit_specifications s
		LEFT JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
		ORDER BY s.database_specification_id`
	rows, err := client.QueryContext(mssqlContext(), q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var specID int64
		var name, auditName string
		var isEnabled bool
		if err := rows.Scan(&specID, &name, &isEnabled, &auditName); err != nil {
			return nil, err
		}
		groups := details[specID]
		if groups == nil {
			groups = map[string]any{}
		}
		audited := actions[specID]
		if audited == nil {
			audited = []any{}
		}
		res, err := CreateResource(c.MqlRuntime, "mssql.auditSpecification", map[string]*llx.RawData{
			"__id":           llx.StringData(c.__id + "/dbAuditSpec/" + name),
			"name":           llx.StringData(name),
			"isEnabled":      llx.BoolData(isEnabled),
			"auditName":      llx.StringData(auditName),
			"actionGroups":   llx.MapData(groups, types.String),
			"auditedActions": llx.ArrayData(audited, types.String),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

// backupTypeDesc maps the single-character backup type code to a readable name.
func backupTypeDesc(code string) string {
	switch code {
	case "D":
		return "DATABASE"
	case "I":
		return "DIFFERENTIAL"
	case "L":
		return "LOG"
	case "F":
		return "FILE"
	case "G":
		return "DIFFERENTIAL_FILE"
	case "P":
		return "PARTIAL"
	case "Q":
		return "DIFFERENTIAL_PARTIAL"
	default:
		return code
	}
}

func (c *mqlMssqlDatabase) backups() ([]any, error) {
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	const q = `SELECT CONVERT(NVARCHAR(36), backup_set_uuid), ISNULL(database_name, ''),
		ISNULL(type, ''), is_copy_only, ISNULL(key_algorithm, ''),
		backup_start_date, backup_finish_date
		FROM msdb.dbo.backupset WHERE database_name = @p1
		ORDER BY backup_finish_date DESC`
	rows, err := client.QueryContext(mssqlContext(), q, sql.Named("p1", c.Name.Data))
	if err != nil {
		// Backup history lives in msdb, which may be refused or absent (Azure
		// SQL Database); a refusal is not "no backups".
		return refusedList(err, "SELECT ON msdb.dbo.backupset")
	}
	defer rows.Close()

	instanceID := mssqlConnection(c.MqlRuntime).InstanceID()
	list := []any{}
	for rows.Next() {
		var uuid, databaseName, typeCode, keyAlgorithm string
		var isCopyOnly bool
		var startDate, finishDate sql.NullTime
		if err := rows.Scan(&uuid, &databaseName, &typeCode, &isCopyOnly, &keyAlgorithm,
			&startDate, &finishDate); err != nil {
			return nil, err
		}
		res, err := CreateResource(c.MqlRuntime, "mssql.backup", map[string]*llx.RawData{
			"__id":             llx.StringData(instanceID + "/backup/" + uuid),
			"backupSetUuid":    llx.StringData(uuid),
			"databaseName":     llx.StringData(databaseName),
			"type":             llx.StringData(backupTypeDesc(typeCode)),
			"isEncrypted":      llx.BoolData(keyAlgorithm != ""),
			"keyAlgorithm":     llx.StringData(keyAlgorithm),
			"isCopyOnly":       llx.BoolData(isCopyOnly),
			"backupStartDate":  llx.TimeDataPtr(nullTime(startDate)),
			"backupFinishDate": llx.TimeDataPtr(nullTime(finishDate)),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}
