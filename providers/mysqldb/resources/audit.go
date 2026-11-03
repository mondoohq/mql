// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	mysqldriver "github.com/go-sql-driver/mysql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

const keyringStatusPermission = "SELECT ON performance_schema.keyring_component_status"

// readKeyringComponentStatus reads performance_schema.keyring_component_status
// into a STATUS_KEY to STATUS_VALUE map. It returns a nil map when the table
// does not exist (MariaDB, MySQL before 8.0.24) and an empty map when no
// keyring component is loaded. Access-denied errors are returned as is.
func readKeyringComponentStatus(db *sql.DB) (map[string]string, error) {
	rows, err := db.QueryContext(mysqldbContext(),
		"SELECT STATUS_KEY, STATUS_VALUE FROM performance_schema.keyring_component_status")
	if err != nil {
		if isMissingTable(err) {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	status := map[string]string{}
	for rows.Next() {
		var k, v sql.NullString
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		status[k.String] = v.String
	}
	return status, rows.Err()
}

func (r *mqlMysqldbInstance) keyringComponentStatus() (*mqlMysqldbKeyringComponentStatus, error) {
	db, err := mysqldbClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	status, err := readKeyringComponentStatus(db)
	if err != nil {
		if !isAccessDenied(err) {
			return nil, err
		}
		if plugin.StructuredErrors() {
			return nil, llx.Forbidden(err, llx.WithPermissions(keyringStatusPermission))
		}
		// v14 keeps a refusal null, as activeKeyringComponent does for
		// components; StructuredErrors turns it into Forbidden above.
		r.KeyringComponentStatus.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// A missing table (nil map) or an empty one means no keyring component is
	// loaded through the manifest.
	if status["Component_name"] == "" {
		r.KeyringComponentStatus.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	properties := make(map[string]any, len(status))
	for k, v := range status {
		properties[k] = v
	}
	res, err := CreateResource(r.MqlRuntime, "mysqldb.keyringComponentStatus", map[string]*llx.RawData{
		"__id":               llx.StringData(r.__id + "/keyring/" + status["Component_name"]),
		"componentName":      llx.StringData(status["Component_name"]),
		"implementationName": llx.StringData(status["Implementation_name"]),
		"author":             llx.StringData(status["Author"]),
		"license":            llx.StringData(status["License"]),
		"version":            llx.StringData(status["Version"]),
		"status":             llx.StringData(status["Component_status"]),
		"dataFile":           llx.StringData(status["Data_file"]),
		"readOnly":           llx.BoolData(isYes(strings.ToUpper(status["Read_only"]))),
		"properties":         llx.MapData(properties, types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMysqldbKeyringComponentStatus), nil
}

// auditLogDatabase returns the schema holding the audit log filter tables.
// MySQL 8.0.33 added audit_log_database to move them out of mysql; without
// the variable (older servers, or the audit plugin not loaded) they are in
// mysql.
func auditLogDatabase(db *sql.DB) (string, error) {
	var name sql.NullString
	err := db.QueryRowContext(mysqldbContext(), "SELECT @@global.audit_log_database").Scan(&name)
	if err != nil {
		if isUnknownSystemVariable(err) {
			return "mysql", nil
		}
		return "", err
	}
	if name.String == "" {
		return "mysql", nil
	}
	return name.String, nil
}

// isUnknownSystemVariable reports whether the server does not know a system
// variable (ER_UNKNOWN_SYSTEM_VARIABLE).
func isUnknownSystemVariable(err error) bool {
	var myErr *mysqldriver.MySQLError
	return errors.As(err, &myErr) && myErr.Number == 1193
}

// quoteIdentifier quotes a schema or table name for use in a statement.
func quoteIdentifier(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

// auditLogQuery runs a query against one of the audit log filter tables.
// It returns nil rows and no error when the table does not exist, which means
// the audit log filter tables are not installed.
func (r *mqlMysqldbInstance) auditLogQuery(table, columns string) (*sql.Rows, string, error) {
	db, err := mysqldbClient(r.MqlRuntime)
	if err != nil {
		return nil, "", err
	}
	schema, err := auditLogDatabase(db)
	if err != nil {
		return nil, "", err
	}
	qualified := quoteIdentifier(schema) + "." + quoteIdentifier(table)
	rows, err := db.QueryContext(mysqldbContext(), "SELECT "+columns+" FROM "+qualified)
	if err != nil {
		if isMissingTable(err) {
			return nil, qualified, nil
		}
		return nil, qualified, err
	}
	return rows, qualified, nil
}

func (r *mqlMysqldbInstance) auditLogFilters() ([]any, error) {
	rows, table, err := r.auditLogQuery("audit_log_filter", "NAME, FILTER")
	if err != nil {
		if isAccessDenied(err) {
			return refusedList(err, "SELECT ON "+table)
		}
		return nil, err
	}
	if rows == nil {
		r.AuditLogFilters.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name string
		var filter sql.NullString
		if err := rows.Scan(&name, &filter); err != nil {
			return nil, err
		}
		definition, err := parseAuditLogFilter(filter.String)
		if err != nil {
			return nil, llx.MalformedData(fmt.Errorf("audit log filter %q: %w", name, err))
		}
		res, err := CreateResource(r.MqlRuntime, "mysqldb.auditLogFilter", map[string]*llx.RawData{
			"__id":       llx.StringData(r.__id + "/auditLogFilter/" + name),
			"name":       llx.StringData(name),
			"definition": llx.DictData(definition),
			"logsAll":    llx.BoolData(auditLogFilterLogsAll(definition)),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (r *mqlMysqldbInstance) auditLogUsers() ([]any, error) {
	rows, table, err := r.auditLogQuery("audit_log_user", "USER, HOST, FILTERNAME")
	if err != nil {
		if isAccessDenied(err) {
			return refusedList(err, "SELECT ON "+table)
		}
		return nil, err
	}
	if rows == nil {
		r.AuditLogUsers.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	defer rows.Close()

	type binding struct{ user, host, filterName string }
	var bindings []binding
	for rows.Next() {
		var b binding
		if err := rows.Scan(&b.user, &b.host, &b.filterName); err != nil {
			return nil, err
		}
		bindings = append(bindings, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	filters := r.GetAuditLogFilters()
	if filters.Error != nil {
		return nil, filters.Error
	}
	byName := map[string]*mqlMysqldbAuditLogFilter{}
	for _, x := range filters.Data {
		f := x.(*mqlMysqldbAuditLogFilter)
		byName[f.Name.Data] = f
	}

	list := []any{}
	for _, b := range bindings {
		filter := llx.NilData
		if f, ok := byName[b.filterName]; ok {
			filter = llx.ResourceData(f, "mysqldb.auditLogFilter")
		}
		res, err := CreateResource(r.MqlRuntime, "mysqldb.auditLogUser", map[string]*llx.RawData{
			"__id":       llx.StringData(r.__id + "/auditLogUser/" + b.user + "@" + b.host),
			"user":       llx.StringData(b.user),
			"host":       llx.StringData(b.host),
			"filterName": llx.StringData(b.filterName),
			"filter":     filter,
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

// parseAuditLogFilter decodes the FILTER column of audit_log_filter, a JSON
// document such as {"filter": {"log": true}}.
func parseAuditLogFilter(raw string) (any, error) {
	if raw == "" {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil, err
	}
	return v, nil
}

// auditLogFilterLogsAll reports whether a filter definition logs every event.
// Per the MySQL Enterprise Audit filter rules, a filter's log item applies to
// all events; without one, logging is on only when the filter has no class or
// event items. A filter naming classes or events logs part of the activity,
// so only a filter with neither, and a log item absent or true, logs all.
func auditLogFilterLogsAll(definition any) bool {
	doc, ok := definition.(map[string]any)
	if !ok {
		return false
	}
	filter, ok := doc["filter"].(map[string]any)
	if !ok {
		return false
	}
	if _, ok := filter["class"]; ok {
		return false
	}
	if _, ok := filter["event"]; ok {
		return false
	}
	log, ok := filter["log"]
	if !ok {
		return true
	}
	b, ok := log.(bool)
	return ok && b
}
