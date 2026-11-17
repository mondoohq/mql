// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

func (r *mqlYugabyteYsql) id() (string, error) {
	return "yugabyte.ysql", nil
}

func (r *mqlYugabyteYsql) version() (string, error) {
	rows, err := ysqlQuery(r.MqlRuntime, `SELECT version()`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var v string
	for rows.Next() {
		if err := rows.Scan(&v); err != nil {
			return "", err
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if v == "" {
		return "", errors.New("YSQL returned no version")
	}
	return v, nil
}

func (r *mqlYugabyteYsql) authenticationEnabled() (bool, error) {
	return tserverFlagEverywhere(r.MqlRuntime, "ysql_enable_auth")
}

func (r *mqlYugabyteYsql) tlsEnabled() (bool, error) {
	return tserverFlagEverywhere(r.MqlRuntime, "use_client_to_server_encryption")
}

func (r *mqlYugabyteYsql) settings() ([]any, error) {
	rows, err := ysqlQuery(r.MqlRuntime, `SELECT name, COALESCE(setting, ''), COALESCE(source, ''), COALESCE(context, ''), COALESCE(pending_restart, false)
		FROM pg_catalog.pg_settings ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []any{}
	for rows.Next() {
		var name, value, source, context string
		var pending bool
		if err := rows.Scan(&name, &value, &source, &context, &pending); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "yugabyte.ysql.setting", map[string]*llx.RawData{
			"__id":           llx.StringData("yugabyte.ysql.setting/" + name),
			"name":           llx.StringData(name),
			"value":          llx.StringData(value),
			"source":         llx.StringData(source),
			"context":        llx.StringData(context),
			"pendingRestart": llx.BoolData(pending),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

// hbaRow is one row of pg_hba_file_rules.
type hbaRow struct {
	lineNumber int64
	ruleType   string
	databases  []string
	users      []string
	address    string
	netmask    string
	method     string
	options    []string
	err        string
}

func (r *mqlYugabyteYsql) hbaRules() ([]any, error) {
	rows, err := ysqlQuery(r.MqlRuntime, `SELECT COALESCE(line_number, 0), COALESCE(type, ''),
		COALESCE(database, ARRAY[]::text[]), COALESCE(user_name, ARRAY[]::text[]),
		COALESCE(address, ''), COALESCE(netmask, ''), COALESCE(auth_method, ''),
		COALESCE(options, ARRAY[]::text[]), COALESCE(error, '')
		FROM pg_catalog.pg_hba_file_rules ORDER BY line_number`)
	if err != nil {
		return nil, refused(err, "superuser (SELECT ON pg_hba_file_rules)")
	}
	defer rows.Close()
	list := []any{}
	for rows.Next() {
		var row hbaRow
		if err := rows.Scan(&row.lineNumber, &row.ruleType, &row.databases, &row.users,
			&row.address, &row.netmask, &row.method, &row.options, &row.err); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "yugabyte.ysql.hbaRule", hbaArgs(row))
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func hbaArgs(row hbaRow) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":       llx.StringData("yugabyte.ysql.hbaRule/" + strconv.FormatInt(row.lineNumber, 10)),
		"lineNumber": llx.IntData(row.lineNumber),
		"type":       llx.StringData(row.ruleType),
		"databases":  llx.ArrayData(toAnySlice(row.databases), types.String),
		"users":      llx.ArrayData(toAnySlice(row.users), types.String),
		"address":    llx.StringData(row.address),
		"netmask":    llx.StringData(row.netmask),
		"method":     llx.StringData(row.method),
		"options":    llx.MapData(parseHBAOptions(row.options), types.String),
		"error":      llx.StringData(row.err),
	}
}

// parseHBAOptions turns the name=value entries of pg_hba_file_rules.options
// into a map. An entry without "=" maps to an empty value.
func parseHBAOptions(options []string) map[string]any {
	out := make(map[string]any, len(options))
	for _, opt := range options {
		k, v, _ := strings.Cut(opt, "=")
		out[k] = v
	}
	return out
}

func (r *mqlYugabyteYsql) databases() ([]any, error) {
	rows, err := ysqlQuery(r.MqlRuntime, `SELECT d.datname, pg_catalog.pg_get_userbyid(d.datdba), d.datallowconn, d.datistemplate, d.datconnlimit
		FROM pg_catalog.pg_database d ORDER BY d.datname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []any{}
	for rows.Next() {
		var name, owner string
		var allowConn, isTemplate bool
		var connLimit int64
		if err := rows.Scan(&name, &owner, &allowConn, &isTemplate, &connLimit); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "yugabyte.ysql.database", map[string]*llx.RawData{
			"__id":             llx.StringData("yugabyte.ysql.database/" + name),
			"name":             llx.StringData(name),
			"allowConnections": llx.BoolData(allowConn),
			"isTemplate":       llx.BoolData(isTemplate),
			"connectionLimit":  llx.IntData(connLimit),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlYugabyteYsqlDatabase).ownerName = owner
		list = append(list, res)
	}
	return list, rows.Err()
}

type mqlYugabyteYsqlDatabaseInternal struct {
	ownerName string
}

func (r *mqlYugabyteYsqlDatabase) owner() (*mqlYugabyteYsqlRole, error) {
	return resolveRole(r.MqlRuntime, r.ownerName, &r.Owner)
}

func (r *mqlYugabyteYsql) extensions() ([]any, error) {
	rows, err := ysqlQuery(r.MqlRuntime, `SELECT e.extname, e.extversion, n.nspname
		FROM pg_catalog.pg_extension e JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace
		ORDER BY e.extname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []any{}
	for rows.Next() {
		var name, version, schema string
		if err := rows.Scan(&name, &version, &schema); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "yugabyte.ysql.extension", map[string]*llx.RawData{
			"__id":    llx.StringData("yugabyte.ysql.extension/" + name),
			"name":    llx.StringData(name),
			"version": llx.StringData(version),
			"schema":  llx.StringData(schema),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}
