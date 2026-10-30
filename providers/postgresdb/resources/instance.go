// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// initPostgresdbInstance fetches the server's core properties once and populates
// the instance resource. Collections resolve lazily through their accessors.
func initPostgresdbInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// The instance is a singleton with no user-facing key; init always populates
	// all scalar fields, so only skip when a full set (8: __id + 7 scalars) is
	// already provided (recording replay or explicit construction).
	if len(args) > 7 {
		return args, nil, nil
	}

	conn := pgConnection(runtime)
	systemID, err := conn.SystemID()
	if err != nil {
		return nil, nil, err
	}
	pool, err := conn.Client("")
	if err != nil {
		return nil, nil, err
	}

	var version string
	var startTime time.Time
	var inRecovery bool
	if err := pool.QueryRow(pgContext(),
		"SELECT version(), pg_postmaster_start_time(), pg_is_in_recovery()").
		Scan(&version, &startTime, &inRecovery); err != nil {
		return nil, nil, err
	}

	// A handful of settings are surfaced directly on the instance.
	settings := map[string]string{}
	rows, err := pool.Query(pgContext(),
		"SELECT name, setting FROM pg_settings WHERE name IN ('ssl', 'password_encryption', 'listen_addresses')")
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var name, setting string
		if err := rows.Scan(&name, &setting); err != nil {
			rows.Close()
			return nil, nil, err
		}
		settings[name] = setting
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	args["__id"] = llx.StringData(systemID)
	args["systemIdentifier"] = llx.StringData(systemID)
	args["version"] = llx.StringData(version)
	args["versionBanner"] = llx.StringData(version)
	args["startTime"] = llx.TimeDataPtr(&startTime)
	args["inRecovery"] = llx.BoolData(inRecovery)
	args["ssl"] = llx.BoolData(settings["ssl"] == "on")
	args["passwordEncryption"] = llx.StringData(settings["password_encryption"])
	args["listenAddresses"] = llx.StringData(settings["listen_addresses"])
	return args, nil, nil
}

func (r *mqlPostgresdbInstance) settings() ([]any, error) {
	pool, err := pgPool(r.MqlRuntime, "")
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(pgContext(),
		`SELECT name, setting, COALESCE(unit, ''), COALESCE(category, ''),
			context, source, COALESCE(boot_val, ''), COALESCE(reset_val, ''), `+pgColumn(r.MqlRuntime, pgVersion95, "pending_restart", "false")+`
		 FROM pg_settings ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, setting, unit, category, context, source, bootVal, resetVal string
		var pendingRestart bool
		if err := rows.Scan(&name, &setting, &unit, &category, &context, &source,
			&bootVal, &resetVal, &pendingRestart); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "postgresdb.setting", map[string]*llx.RawData{
			"__id":           llx.StringData(r.SystemIdentifier.Data + "/setting/" + name),
			"name":           llx.StringData(name),
			"setting":        llx.StringData(setting),
			"unit":           llx.StringData(unit),
			"category":       llx.StringData(category),
			"context":        llx.StringData(context),
			"source":         llx.StringData(source),
			"bootValue":      llx.StringData(bootVal),
			"resetValue":     llx.StringData(resetVal),
			"pendingRestart": llx.BoolData(pendingRestart),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

// hbaRulesQuery selects pg_hba_file_rules for a server version. PostgreSQL 16
// added include directives together with file_name and rule_number: from then
// on line_number is relative to file_name, and rule_number is the order in
// which the server evaluates the rules. An invalid line is reported with NULL
// type, database, user_name and rule_number and a message in error, so every
// column is coalesced to keep that row (and the rest of the list) readable.
func hbaRulesQuery(serverVersionNum int64) string {
	const cols = `COALESCE(line_number, 0), COALESCE(type, ''), COALESCE(database, '{}'),
			COALESCE(user_name, '{}'), COALESCE(address, ''), COALESCE(netmask, ''),
			COALESCE(auth_method, ''), COALESCE(options, '{}'), COALESCE(error, '')`
	if serverVersionNum >= 160000 {
		return `SELECT COALESCE(file_name, ''), ` + cols + `
		 FROM pg_hba_file_rules ORDER BY rule_number NULLS LAST, file_name, line_number`
	}
	return `SELECT '', ` + cols + `
		 FROM pg_hba_file_rules ORDER BY line_number`
}

// hbaRuleResourceID keys a rule by its file and line. Servers before 16 report
// no file, and their ids keep the line-only form.
func hbaRuleResourceID(systemID, file string, lineNumber int64) string {
	if file == "" {
		return systemID + "/hba/" + intToStr(lineNumber)
	}
	return systemID + "/hba/" + file + ":" + intToStr(lineNumber)
}

func (r *mqlPostgresdbInstance) hbaRules() ([]any, error) {
	pool, err := pgPool(r.MqlRuntime, "")
	if err != nil {
		return nil, err
	}
	var versionNum int64
	if err := pool.QueryRow(pgContext(),
		"SELECT current_setting('server_version_num')::bigint").Scan(&versionNum); err != nil {
		return nil, err
	}
	// pg_hba_file_rules is restricted to superusers / pg_read_all_settings;
	// treat only a permission error as no visible rules, and propagate the rest.
	rows, err := pool.Query(pgContext(), hbaRulesQuery(versionNum))
	if err != nil {
		if isPermissionDenied(err) {
			return []any{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var lineNumber int64
		var file, typ, address, netmask, authMethod, ruleError string
		var databases, userNames, options []string
		if err := rows.Scan(&file, &lineNumber, &typ, &databases, &userNames, &address,
			&netmask, &authMethod, &options, &ruleError); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "postgresdb.hbaRule", map[string]*llx.RawData{
			"__id":       llx.StringData(hbaRuleResourceID(r.SystemIdentifier.Data, file, lineNumber)),
			"file":       llx.StringData(file),
			"lineNumber": llx.IntData(lineNumber),
			"type":       llx.StringData(typ),
			"databases":  llx.ArrayData(strSliceToAny(databases), types.String),
			"userNames":  llx.ArrayData(strSliceToAny(userNames), types.String),
			"address":    llx.StringData(address),
			"netmask":    llx.StringData(netmask),
			"authMethod": llx.StringData(authMethod),
			"options":    llx.ArrayData(strSliceToAny(options), types.String),
			"error":      llx.StringData(ruleError),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

// strSliceToAny converts a []string to []any for llx.ArrayData.
func strSliceToAny(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}
