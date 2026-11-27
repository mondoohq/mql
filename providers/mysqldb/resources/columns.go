// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/mysqldb/connection"
)

type mqlMysqldbTableInternal struct {
	// cacheSchemaColumns is shared by every table one schema.tables() call
	// lists, so reading the columns of all of them costs one query.
	cacheSchemaColumns *mysqlSchemaColumns
}

// mysqlColumnsQuery lists the columns of every table and view in one schema.
// COLUMN_TYPE carries the full declared type (varchar(255), int unsigned);
// DATA_TYPE would drop the length and the sign.
const mysqlColumnsQuery = `SELECT TABLE_NAME, COLUMN_NAME, ORDINAL_POSITION, COLUMN_TYPE,
		IS_NULLABLE, COALESCE(COLUMN_COMMENT, '')
	 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ?
	 ORDER BY TABLE_NAME, ORDINAL_POSITION`

// mysqlColumnsPermission is the privilege that makes information_schema.COLUMNS
// list every column.
const mysqlColumnsPermission = "SELECT ON *.*"

// mysqlColumnRow is one row of mysqlColumnsQuery.
type mysqlColumnRow struct {
	table, name, typeName, comment string
	position                       int64
	nullable                       bool
}

// mysqlRowScanner is the part of sql.Rows that groupMysqlColumnRows reads, so
// the grouping can be tested without a server.
type mysqlRowScanner interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}

// groupMysqlColumnRows reads mysqlColumnsQuery rows and groups them by table,
// keeping the position order.
func groupMysqlColumnRows(rows mysqlRowScanner) (map[string][]mysqlColumnRow, error) {
	byTable := map[string][]mysqlColumnRow{}
	for rows.Next() {
		var c mysqlColumnRow
		var isNullable string
		if err := rows.Scan(&c.table, &c.name, &c.position, &c.typeName, &isNullable, &c.comment); err != nil {
			return nil, err
		}
		c.nullable = isNullable == "YES"
		byTable[c.table] = append(byTable[c.table], c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return byTable, nil
}

// columnsVisible refuses a columns read by a caller without global SELECT.
//
// information_schema.COLUMNS lists only the columns the caller holds a
// privilege on and raises no error, so a narrower account would read a table
// with fewer columns as if it were complete. The field is new, so the refusal
// is an error whatever StructuredErrors says.
func columnsVisible(access *connection.CallerAccess) error {
	if access.CanListTables() {
		return nil
	}
	return llx.Forbidden(
		fmt.Errorf("%s cannot see every column: information_schema lists only the columns it holds privileges on", access.Self),
		llx.WithPermissions(mysqlColumnsPermission))
}

// classifyMysqlColumnsError turns an access-denied error into Forbidden; any
// other error is returned as is.
func classifyMysqlColumnsError(err error) error {
	if err != nil && isAccessDenied(err) {
		return llx.Forbidden(err, llx.WithPermissions(mysqlColumnsPermission))
	}
	return err
}

// mysqlSchemaColumns memoizes the columns of one schema, with the error.
type mysqlSchemaColumns struct {
	once    sync.Once
	byTable map[string][]mysqlColumnRow
	err     error
}

// load runs fetch once and returns its outcome on every call.
func (c *mysqlSchemaColumns) load(fetch func() (map[string][]mysqlColumnRow, error)) (map[string][]mysqlColumnRow, error) {
	c.once.Do(func() {
		c.byTable, c.err = fetch()
	})
	return c.byTable, c.err
}

func (r *mqlMysqldbTable) columns() ([]any, error) {
	access, err := mysqldbConnection(r.MqlRuntime).CallerAccess()
	if err != nil {
		return nil, err
	}
	if err := columnsVisible(access); err != nil {
		return nil, err
	}
	if r.cacheSchemaColumns == nil {
		r.cacheSchemaColumns = &mysqlSchemaColumns{}
	}
	byTable, err := r.cacheSchemaColumns.load(func() (map[string][]mysqlColumnRow, error) {
		db, err := mysqldbClient(r.MqlRuntime)
		if err != nil {
			return nil, err
		}
		rows, err := db.QueryContext(mysqldbContext(), mysqlColumnsQuery, r.Schema.Data)
		if err != nil {
			return nil, classifyMysqlColumnsError(err)
		}
		defer rows.Close()
		byTable, err := groupMysqlColumnRows(rows)
		return byTable, classifyMysqlColumnsError(err)
	})
	if err != nil {
		return nil, err
	}

	list := []any{}
	for _, c := range byTable[r.Name.Data] {
		res, err := CreateResource(r.MqlRuntime, "mysqldb.table.column", map[string]*llx.RawData{
			"__id":     llx.StringData(r.__id + "/column/" + c.name),
			"name":     llx.StringData(c.name),
			"position": llx.IntData(c.position),
			"typeName": llx.StringData(c.typeName),
			"nullable": llx.BoolData(c.nullable),
			"comment":  llx.StringData(c.comment),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}
