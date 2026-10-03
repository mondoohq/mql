// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"database/sql"
	"fmt"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// initMssqlServer fetches the instance's core properties once and populates the
// server resource. Computed collections and registry-backed fields are resolved
// lazily by their own accessors.
func initMssqlServer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// already populated (recording or explicit args)
	if len(args) > 3 {
		return args, nil, nil
	}

	conn := mssqlConnection(runtime)
	client, err := conn.Client()
	if err != nil {
		return nil, nil, err
	}

	const query = `
		SELECT
			CAST(SERVERPROPERTY('ServerName') AS NVARCHAR(256)),
			CAST(SERVERPROPERTY('MachineName') AS NVARCHAR(256)),
			CAST(SERVERPROPERTY('InstanceName') AS NVARCHAR(256)),
			CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128)),
			CAST(SERVERPROPERTY('ProductLevel') AS NVARCHAR(128)),
			CAST(SERVERPROPERTY('ProductUpdateLevel') AS NVARCHAR(128)),
			CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128)),
			CAST(SERVERPROPERTY('IsClustered') AS INT),
			CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS INT),
			@@VERSION`

	var name, machine, instance, productVersion, productLevel, productUpdateLevel, edition, version sql.NullString
	var isClustered, integratedOnly sql.NullInt64
	err = client.QueryRowContext(mssqlContext(), query).Scan(
		&name, &machine, &instance, &productVersion, &productLevel, &productUpdateLevel, &edition,
		&isClustered, &integratedOnly, &version)
	if err != nil {
		return nil, nil, err
	}

	instanceName := instance.String
	if instanceName == "" {
		instanceName = "MSSQLSERVER"
	}

	args["__id"] = llx.StringData(conn.InstanceID())
	args["name"] = llx.StringData(name.String)
	args["machineName"] = llx.StringData(machine.String)
	args["instanceName"] = llx.StringData(instanceName)
	args["version"] = llx.StringData(version.String)
	args["versionBanner"] = llx.StringData(version.String)
	args["productVersion"] = llx.StringData(productVersion.String)
	args["productLevel"] = llx.StringData(productLevel.String)
	args["productUpdateLevel"] = nullString(productUpdateLevel)
	args["edition"] = llx.StringData(edition.String)
	args["isClustered"] = llx.BoolData(isClustered.Int64 == 1)
	// IsIntegratedSecurityOnly == 1 means Windows-only auth; mixed mode is the negation.
	args["isMixedModeAuthEnabled"] = llx.BoolData(integratedOnly.Int64 == 0)

	return args, nil, nil
}

func (c *mqlMssqlServer) instanceID() string {
	return mssqlConnection(c.MqlRuntime).InstanceID()
}

// port reports the TCP port the instance is listening on, taken from the
// scanning session's own row in sys.dm_exec_connections. A session always sees
// its own connection, so no VIEW SERVER STATE is required. The port the scan
// dialed is only a fallback: it is the wrong answer whenever a port mapping or
// proxy sits in front of the instance, which is exactly the case the
// non-standard-port audit needs to get right.
func (c *mqlMssqlServer) port() (int64, error) {
	fallback := int64(mssqlConnection(c.MqlRuntime).Port())

	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return fallback, nil
	}
	const q = `SELECT local_tcp_port FROM sys.dm_exec_connections WHERE session_id = @@SPID`
	var v sql.NullInt64
	if err := client.QueryRowContext(mssqlContext(), q).Scan(&v); err != nil || !v.Valid || v.Int64 == 0 {
		// Shared memory and named-pipe sessions report no TCP port.
		return fallback, nil
	}
	return v.Int64, nil
}

// --- registry-backed fields -------------------------------------------------

// regReadInt reads an integer registry value through xp_instance_regread. The
// bool result reports whether the value could be read; unreadable values (Linux,
// missing privilege, absent key) return ok=false so the caller can surface null.
func (c *mqlMssqlServer) regReadInt(key, valueName string) (int64, bool) {
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return 0, false
	}
	const q = `DECLARE @v INT;
		EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', @p1, @p2, @v OUTPUT;
		SELECT @v`
	var v sql.NullInt64
	if err := client.QueryRowContext(mssqlContext(), q,
		sql.Named("p1", key), sql.Named("p2", valueName)).Scan(&v); err != nil {
		return 0, false
	}
	if !v.Valid {
		return 0, false
	}
	return v.Int64, true
}

const superSocketNetLib = `Software\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib`
const mssqlServerKey = `Software\Microsoft\MSSQLServer\MSSQLServer`

func (c *mqlMssqlServer) forceEncryption() (bool, error) {
	v, ok := c.regReadInt(superSocketNetLib, "ForceEncryption")
	if !ok {
		c.ForceEncryption.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return v == 1, nil
}

func (c *mqlMssqlServer) extendedProtection() (string, error) {
	v, ok := c.regReadInt(superSocketNetLib, "ExtendedProtection")
	if !ok {
		c.ExtendedProtection.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	switch v {
	case 0:
		return "Off", nil
	case 1:
		return "Allowed", nil
	case 2:
		return "Required", nil
	default:
		return fmt.Sprintf("Unknown(%d)", v), nil
	}
}

func (c *mqlMssqlServer) hideInstance() (bool, error) {
	v, ok := c.regReadInt(superSocketNetLib, "HideInstance")
	if !ok {
		c.HideInstance.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return v == 1, nil
}

func (c *mqlMssqlServer) errorLogFileCount() (int64, error) {
	v, ok := c.regReadInt(mssqlServerKey, "NumErrorLogs")
	if !ok {
		c.ErrorLogFileCount.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return v, nil
}

func (c *mqlMssqlServer) loginAuditLevel() (string, error) {
	v, ok := c.regReadInt(mssqlServerKey, "AuditLevel")
	if !ok {
		c.LoginAuditLevel.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	switch v {
	case 0:
		return "None", nil
	case 1:
		return "Successful", nil
	case 2:
		return "Failed", nil
	case 3:
		return "All", nil
	default:
		return fmt.Sprintf("Unknown(%d)", v), nil
	}
}

func (c *mqlMssqlServer) serviceAccount() (string, error) {
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return "", err
	}
	const q = `SELECT service_account FROM sys.dm_server_services
		WHERE servicename LIKE 'SQL Server (%' AND servicename NOT LIKE 'SQL Server Agent%'`
	var acct sql.NullString
	if err := client.QueryRowContext(mssqlContext(), q).Scan(&acct); err != nil {
		// Not available on Linux or without VIEW SERVER STATE; report as null.
		c.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return acct.String, nil
}

func (c *mqlMssqlServer) serviceAccountSid() (string, error) {
	acct := c.GetServiceAccount()
	if acct.Error != nil {
		return "", acct.Error
	}
	if acct.Data == "" {
		c.ServiceAccountSid.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return "", err
	}
	var sid []byte
	if err := client.QueryRowContext(mssqlContext(),
		"SELECT SUSER_SID(@p1)", sql.Named("p1", acct.Data)).Scan(&sid); err != nil || len(sid) == 0 {
		c.ServiceAccountSid.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return sidString(sid), nil
}

func (c *mqlMssqlServer) servicePrincipalNames() ([]any, error) {
	// SPN discovery requires an Active Directory lookup, which the base provider
	// does not perform; report as null rather than an empty (misleading) list.
	c.ServicePrincipalNames.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// --- collections ------------------------------------------------------------

func (c *mqlMssqlServer) configurations() ([]any, error) {
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	const q = `SELECT name,
		CONVERT(BIGINT, ISNULL(value, 0)), CONVERT(BIGINT, ISNULL(value_in_use, 0)),
		CONVERT(BIGINT, minimum), CONVERT(BIGINT, maximum), is_dynamic, is_advanced
		FROM sys.configurations ORDER BY name`
	rows, err := client.QueryContext(mssqlContext(), q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	instanceID := c.instanceID()
	list := []any{}
	for rows.Next() {
		var name string
		var value, valueInUse, minimum, maximum int64
		var isDynamic, isAdvanced bool
		if err := rows.Scan(&name, &value, &valueInUse, &minimum, &maximum, &isDynamic, &isAdvanced); err != nil {
			return nil, err
		}
		res, err := CreateResource(c.MqlRuntime, "mssql.server.configuration", map[string]*llx.RawData{
			"__id":       llx.StringData(instanceID + "/config/" + name),
			"name":       llx.StringData(name),
			"value":      llx.IntData(value),
			"valueInUse": llx.IntData(valueInUse),
			"minimum":    llx.IntData(minimum),
			"maximum":    llx.IntData(maximum),
			"isDynamic":  llx.BoolData(isDynamic),
			"isAdvanced": llx.BoolData(isAdvanced),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (c *mqlMssqlServer) logins() ([]any, error) {
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	q := `SELECT ` + loginColumns + `
		FROM sys.server_principals p
		LEFT JOIN sys.sql_logins sl ON p.principal_id = sl.principal_id
		WHERE p.type IN ('S','U','G','C','K')
		ORDER BY p.principal_id`
	rows, err := client.QueryContext(mssqlContext(), q)
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

func (c *mqlMssqlServer) roles() ([]any, error) {
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	const q = `SELECT principal_id, name, is_fixed_role, ISNULL(owning_principal_id, 0),
		create_date, modify_date
		FROM sys.server_principals WHERE type = 'R' ORDER BY principal_id`
	rows, err := client.QueryContext(mssqlContext(), q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	instanceID := c.instanceID()
	list := []any{}
	for rows.Next() {
		var principalID, owningPid int64
		var name string
		var isFixedRole bool
		var createDate, modifyDate sql.NullTime
		if err := rows.Scan(&principalID, &name, &isFixedRole, &owningPid, &createDate, &modifyDate); err != nil {
			return nil, err
		}
		res, err := newMssqlServerRole(c.MqlRuntime, instanceID, principalID, name, isFixedRole, owningPid, createDate, modifyDate)
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (c *mqlMssqlServer) permissions() ([]any, error) {
	return serverPermissionsFor(c.MqlRuntime, c.instanceID(), nil)
}

func (c *mqlMssqlServer) databases() ([]any, error) {
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	const q = `SELECT d.database_id, d.name,
		d.owner_sid, ISNULL(SUSER_SNAME(d.owner_sid), ''),
		(SELECT sp.principal_id FROM sys.server_principals sp WHERE sp.sid = d.owner_sid),
		d.create_date, d.compatibility_level, ISNULL(d.collation_name, ''),
		d.is_read_only, d.is_trustworthy_on, d.is_encrypted, d.is_auto_close_on,
		d.containment_desc, d.state_desc, d.is_broker_enabled
		FROM sys.databases d ORDER BY d.database_id`
	rows, err := client.QueryContext(mssqlContext(), q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	instanceID := c.instanceID()
	list := []any{}
	for rows.Next() {
		var databaseID, compatLevel int64
		var name, ownerName, collation, containment, stateDesc string
		var ownerSid []byte
		var ownerPrincipalID sql.NullInt64
		var createDate sql.NullTime
		var isReadOnly, isTrustworthy, isEncrypted, isAutoClose, isBroker bool
		if err := rows.Scan(&databaseID, &name, &ownerSid, &ownerName, &ownerPrincipalID, &createDate,
			&compatLevel, &collation, &isReadOnly, &isTrustworthy, &isEncrypted,
			&isAutoClose, &containment, &stateDesc, &isBroker); err != nil {
			return nil, err
		}
		res, err := CreateResource(c.MqlRuntime, "mssql.database", map[string]*llx.RawData{
			"__id":               llx.StringData(databaseIdentifier(instanceID, name)),
			"name":               llx.StringData(name),
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
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (c *mqlMssqlServer) credentials() ([]any, error) {
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	const q = `SELECT name, ISNULL(credential_identity, ''), create_date, modify_date
		FROM sys.credentials ORDER BY credential_id`
	rows, err := client.QueryContext(mssqlContext(), q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	instanceID := c.instanceID()
	list := []any{}
	for rows.Next() {
		var name, identity string
		var createDate, modifyDate sql.NullTime
		if err := rows.Scan(&name, &identity, &createDate, &modifyDate); err != nil {
			return nil, err
		}
		res, err := CreateResource(c.MqlRuntime, "mssql.credential", map[string]*llx.RawData{
			"__id":       llx.StringData(instanceID + "/credential/" + name),
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

func (c *mqlMssqlServer) linkedServers() ([]any, error) {
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	const q = `SELECT name, ISNULL(product, ''), ISNULL(provider, ''), ISNULL(data_source, ''),
		is_rpc_out_enabled, is_data_access_enabled
		FROM sys.servers WHERE server_id <> 0 ORDER BY server_id`
	rows, err := client.QueryContext(mssqlContext(), q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	instanceID := c.instanceID()
	list := []any{}
	for rows.Next() {
		var name, product, provider, dataSource string
		var rpcOut, dataAccess bool
		if err := rows.Scan(&name, &product, &provider, &dataSource, &rpcOut, &dataAccess); err != nil {
			return nil, err
		}
		res, err := CreateResource(c.MqlRuntime, "mssql.linkedServer", map[string]*llx.RawData{
			"__id":                llx.StringData(instanceID + "/linkedserver/" + name),
			"name":                llx.StringData(name),
			"product":             llx.StringData(product),
			"provider":            llx.StringData(provider),
			"dataSource":          llx.StringData(dataSource),
			"isRpcOutEnabled":     llx.BoolData(rpcOut),
			"isDataAccessEnabled": llx.BoolData(dataAccess),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (c *mqlMssqlServer) proxyAccounts() ([]any, error) {
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}

	// Proxies the msdb public role is granted use of (CIS 3.11).
	publicProxies := map[int64]bool{}
	pubRows, err := client.QueryContext(mssqlContext(),
		`SELECT proxy_id FROM msdb.dbo.sysproxylogin
		 WHERE sid = (SELECT sid FROM msdb.sys.database_principals WHERE name = 'public')`)
	if err == nil {
		for pubRows.Next() {
			var proxyID int64
			if err := pubRows.Scan(&proxyID); err != nil {
				pubRows.Close()
				return nil, err
			}
			publicProxies[proxyID] = true
		}
		err = pubRows.Err()
		pubRows.Close()
		if err != nil {
			return nil, err
		}
	}

	// Subsystems for each proxy, collected first so they can be attached inline.
	subsystems := map[int64][]any{}
	subRows, err := client.QueryContext(mssqlContext(),
		`SELECT ps.proxy_id, s.subsystem
		 FROM msdb.dbo.sysproxysubsystem ps
		 JOIN msdb.dbo.syssubsystems s ON ps.subsystem_id = s.subsystem_id`)
	if err == nil {
		for subRows.Next() {
			var proxyID int64
			var subsystem string
			if err := subRows.Scan(&proxyID, &subsystem); err != nil {
				subRows.Close()
				return nil, err
			}
			subsystems[proxyID] = append(subsystems[proxyID], subsystem)
		}
		err = subRows.Err()
		subRows.Close()
		if err != nil {
			return nil, err
		}
	}

	const q = `SELECT p.proxy_id, p.name, ISNULL(c.name, ''), p.enabled
		FROM msdb.dbo.sysproxies p
		LEFT JOIN sys.credentials c ON p.credential_id = c.credential_id
		ORDER BY p.proxy_id`
	rows, err := client.QueryContext(mssqlContext(), q)
	if err != nil {
		// msdb proxy tables require explicit access; treat as no proxies rather
		// than failing the whole query.
		return []any{}, nil
	}
	defer rows.Close()

	instanceID := c.instanceID()
	list := []any{}
	for rows.Next() {
		var proxyID int64
		var name, credentialName string
		var enabled bool
		if err := rows.Scan(&proxyID, &name, &credentialName, &enabled); err != nil {
			return nil, err
		}
		subs := subsystems[proxyID]
		if subs == nil {
			subs = []any{}
		}
		res, err := CreateResource(c.MqlRuntime, "mssql.proxyAccount", map[string]*llx.RawData{
			"__id":                 llx.StringData(instanceID + "/proxy/" + name),
			"name":                 llx.StringData(name),
			"credentialName":       llx.StringData(credentialName),
			"isEnabled":            llx.BoolData(enabled),
			"isAccessibleToPublic": llx.BoolData(publicProxies[proxyID]),
			"subsystems":           llx.ArrayData(subs, types.String),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (c *mqlMssqlServer) audits() ([]any, error) {
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	const q = `SELECT name, is_state_enabled, on_failure_desc, type_desc
		FROM sys.server_audits ORDER BY audit_id`
	rows, err := client.QueryContext(mssqlContext(), q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	instanceID := c.instanceID()
	list := []any{}
	for rows.Next() {
		var name, onFailure, destination string
		var isEnabled bool
		if err := rows.Scan(&name, &isEnabled, &onFailure, &destination); err != nil {
			return nil, err
		}
		res, err := CreateResource(c.MqlRuntime, "mssql.audit", map[string]*llx.RawData{
			"__id":        llx.StringData(instanceID + "/audit/" + name),
			"name":        llx.StringData(name),
			"isEnabled":   llx.BoolData(isEnabled),
			"onFailure":   llx.StringData(onFailure),
			"destination": llx.StringData(destination),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (c *mqlMssqlServer) serverAuditSpecifications() ([]any, error) {
	client, err := mssqlClient(c.MqlRuntime)
	if err != nil {
		return nil, err
	}

	// Action groups per specification, gathered first.
	details := map[int64]map[string]any{}
	actions := map[int64][]any{}
	detailRows, err := client.QueryContext(mssqlContext(),
		`SELECT server_specification_id, audit_action_name, ISNULL(audited_result, ''),
			class_desc, is_group
		 FROM sys.server_audit_specification_details
		 ORDER BY server_specification_id, audit_action_name`)
	if err == nil {
		for detailRows.Next() {
			var specID int64
			var action, result, class string
			var isGroup bool
			if err := detailRows.Scan(&specID, &action, &result, &class, &isGroup); err != nil {
				detailRows.Close()
				return nil, err
			}
			if details[specID] == nil {
				details[specID] = map[string]any{}
			}
			details[specID][action] = result
			actions[specID] = append(actions[specID], auditedAction(action, class, "", "", isGroup))
		}
		err = detailRows.Err()
		detailRows.Close()
		if err != nil {
			return nil, err
		}
	}

	const q = `SELECT s.server_specification_id, s.name, s.is_state_enabled, ISNULL(a.name, '')
		FROM sys.server_audit_specifications s
		LEFT JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
		ORDER BY s.server_specification_id`
	rows, err := client.QueryContext(mssqlContext(), q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	instanceID := c.instanceID()
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
			"__id":           llx.StringData(instanceID + "/serverAuditSpec/" + name),
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

// nullTime converts a sql.NullTime to a *time.Time (nil when not valid) so it
// maps cleanly to a null mql time.
func nullTime(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}
