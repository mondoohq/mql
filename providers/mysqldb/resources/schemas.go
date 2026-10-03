// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/mysqldb/connection"
)

func grantsVisible(a *connection.CallerAccess) bool {
	return a.GrantsVisible
}

func (r *mqlMysqldbInstance) schemas() ([]any, error) {
	if err := requireVisibility(r.MqlRuntime, (*connection.CallerAccess).CanListSchemas, "schema", "SHOW DATABASES ON *.*"); err != nil {
		return nil, err
	}
	db, err := mysqldbClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	serverID := r.__id
	rows, err := db.QueryContext(mysqldbContext(),
		`SELECT SCHEMA_NAME, COALESCE(DEFAULT_CHARACTER_SET_NAME, ''), COALESCE(DEFAULT_COLLATION_NAME, '')
		 FROM information_schema.SCHEMATA ORDER BY SCHEMA_NAME`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, charset, collation string
		if err := rows.Scan(&name, &charset, &collation); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "mysqldb.schema", map[string]*llx.RawData{
			"__id":                llx.StringData(schemaResourceID(serverID, name)),
			"name":                llx.StringData(name),
			"defaultCharacterSet": llx.StringData(charset),
			"defaultCollation":    llx.StringData(collation),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (r *mqlMysqldbSchema) privileges() ([]any, error) {
	if err := requireVisibility(r.MqlRuntime, grantsVisible, "account's schema privileges", "SELECT ON mysql.*"); err != nil {
		return nil, err
	}
	return privilegesForSchema(r.MqlRuntime, r.__id, r.Name.Data)
}

func (r *mqlMysqldbSchema) routines() ([]any, error) {
	if err := requireVisibility(r.MqlRuntime, (*connection.CallerAccess).CanListRoutines, "routine", "SELECT ON *.*"); err != nil {
		return nil, err
	}
	db, err := mysqldbClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(mysqldbContext(),
		`SELECT ROUTINE_NAME, ROUTINE_TYPE, COALESCE(DEFINER, ''), COALESCE(SECURITY_TYPE, ''), COALESCE(IS_DETERMINISTIC, 'NO')
		 FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = ? ORDER BY ROUTINE_NAME`, r.Name.Data)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, routineType, definer, securityType, deterministic string
		if err := rows.Scan(&name, &routineType, &definer, &securityType, &deterministic); err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "mysqldb.routine", map[string]*llx.RawData{
			"__id":            llx.StringData(r.__id + "/routine/" + routineType + "/" + name),
			"name":            llx.StringData(name),
			"schema":          llx.StringData(r.Name.Data),
			"type":            llx.StringData(routineType),
			"definer":         llx.StringData(definer),
			"securityType":    llx.StringData(securityType),
			"isDeterministic": llx.BoolData(isYes(deterministic)),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (r *mqlMysqldbSchema) tables() ([]any, error) {
	if err := requireVisibility(r.MqlRuntime, (*connection.CallerAccess).CanListTables, "table", "SELECT ON *.*"); err != nil {
		return nil, err
	}
	db, err := mysqldbClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(mysqldbContext(),
		`SELECT TABLE_NAME, COALESCE(ENGINE, ''), COALESCE(ROW_FORMAT, ''), COALESCE(CREATE_OPTIONS, '')
		 FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME`, r.Name.Data)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	list := []any{}
	for rows.Next() {
		var name, engine, rowFormat, createOptions string
		if err := rows.Scan(&name, &engine, &rowFormat, &createOptions); err != nil {
			return nil, err
		}
		encrypted := strings.Contains(strings.ToLower(createOptions), "encryption='y'")
		res, err := CreateResource(r.MqlRuntime, "mysqldb.table", map[string]*llx.RawData{
			"__id":      llx.StringData(r.__id + "/table/" + name),
			"name":      llx.StringData(name),
			"schema":    llx.StringData(r.Name.Data),
			"engine":    llx.StringData(engine),
			"rowFormat": llx.StringData(rowFormat),
			"encrypted": llx.BoolData(encrypted),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, rows.Err()
}

func (r *mqlMysqldbTable) privileges() ([]any, error) {
	if err := requireVisibility(r.MqlRuntime, grantsVisible, "account's table privileges", "SELECT ON mysql.*"); err != nil {
		return nil, err
	}
	return privilegesForTable(r.MqlRuntime, r.__id, r.Schema.Data, r.Name.Data)
}
