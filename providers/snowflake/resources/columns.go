// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

// showColumnsCap is the most rows a SHOW command returns. A SHOW COLUMNS IN
// SCHEMA answer of this size may have been cut, so the tables of that schema
// read their columns one table at a time instead.
const showColumnsCap = 10000

// unsafeQuery runs one statement and returns its rows as QueryUnsafe does.
// Tests replace it to count statements.
type unsafeQuery func(ctx context.Context, statement string) ([]map[string]*any, error)

// snowflakeColumnRow is one decoded SHOW COLUMNS row.
type snowflakeColumnRow struct {
	table    string
	name     string
	typeName string
	nullable bool
	comment  string
}

// quoteIdentifier quotes one Snowflake identifier part, doubling any quote it
// contains, so a name with quotes or dots cannot change the statement.
func quoteIdentifier(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// decodeShowColumnsRow reads one SHOW COLUMNS row. data_type is a JSON
// document such as {"type":"TEXT","length":16777216,"nullable":true}; the
// null? cell is the fallback when it carries no nullable key.
func decodeShowColumnsRow(row map[string]*any) (snowflakeColumnRow, error) {
	out := snowflakeColumnRow{
		table:    unsafeString(row["table_name"]),
		name:     unsafeString(row["column_name"]),
		comment:  unsafeString(row["comment"]),
		nullable: unsafeBool(row["null?"]),
	}
	raw := unsafeString(row["data_type"])
	var dataType map[string]any
	if err := json.Unmarshal([]byte(raw), &dataType); err != nil {
		return out, llx.MalformedData(fmt.Errorf("SHOW COLUMNS returned a data_type for %s.%s that is not JSON: %w", out.table, out.name, err))
	}
	if n, ok := dataType["nullable"].(bool); ok {
		out.nullable = n
	}
	out.typeName = formatSnowflakeType(dataType)
	return out, nil
}

// formatSnowflakeType renders a data_type document as the declared type
// DESCRIBE TABLE shows: TEXT with a length is VARCHAR(n), FIXED with a
// precision and scale is NUMBER(p,s), REAL is FLOAT, BINARY carries its length,
// the time types carry their fractional-second scale, and any other type is its
// name.
func formatSnowflakeType(dataType map[string]any) string {
	name, _ := dataType["type"].(string)
	num := func(key string) (string, bool) {
		v, ok := dataType[key].(float64)
		if !ok {
			return "", false
		}
		return strconv.FormatInt(int64(v), 10), true
	}
	switch name {
	case "TEXT":
		if n, ok := num("length"); ok {
			return "VARCHAR(" + n + ")"
		}
		return "VARCHAR"
	case "FIXED":
		p, okP := num("precision")
		s, okS := num("scale")
		if okP && okS {
			return "NUMBER(" + p + "," + s + ")"
		}
		return "NUMBER"
	case "REAL":
		return "FLOAT"
	case "BINARY":
		if n, ok := num("length"); ok {
			return "BINARY(" + n + ")"
		}
	case "TIME", "TIMESTAMP_LTZ", "TIMESTAMP_NTZ", "TIMESTAMP_TZ":
		if s, ok := num("scale"); ok {
			return name + "(" + s + ")"
		}
	}
	return name
}

// schemaColumns is one schema's SHOW COLUMNS answer, keyed by table name.
// truncated means the answer reached showColumnsCap, so a table missing from
// it may only have been cut off.
type schemaColumns struct {
	byTable   map[string][]snowflakeColumnRow
	truncated bool
}

// schemaColumnsMemo holds the outcome of one schema's listing, error included:
// a role refused once is refused for every table of the schema.
type schemaColumnsMemo struct {
	once  sync.Once
	value *schemaColumns
	err   error
}

// schemaColumnsCache holds one memo per database and schema.
type schemaColumnsCache struct {
	lock  sync.Mutex
	memos map[string]*schemaColumnsMemo
}

func (c *schemaColumnsCache) memo(database, schema string) *schemaColumnsMemo {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.memos == nil {
		c.memos = map[string]*schemaColumnsMemo{}
	}
	key := database + "\x00" + schema
	m, ok := c.memos[key]
	if !ok {
		m = &schemaColumnsMemo{}
		c.memos[key] = m
	}
	return m
}

// columnsAccessError turns a refused SHOW COLUMNS into Forbidden naming the
// privilege. The field is new, so this is an error whatever StructuredErrors
// says; any other error is returned as is.
func columnsAccessError(err error, database, schema string) error {
	if isAccessDenied(err) {
		return llx.Forbidden(err, llx.WithPermissions("USAGE ON SCHEMA "+database+"."+schema))
	}
	return err
}

// decodeColumnRows decodes and groups SHOW COLUMNS rows by table.
func decodeColumnRows(rows []map[string]*any) (map[string][]snowflakeColumnRow, error) {
	byTable := map[string][]snowflakeColumnRow{}
	for _, row := range rows {
		c, err := decodeShowColumnsRow(row)
		if err != nil {
			return nil, err
		}
		byTable[c.table] = append(byTable[c.table], c)
	}
	return byTable, nil
}

// tableColumns returns the columns of one table. The schema is listed once per
// scan with SHOW COLUMNS IN SCHEMA and shared by its tables; a schema whose
// answer reached the SHOW row cap is read with SHOW COLUMNS IN TABLE for the
// table asked about, so a large schema is never silently cut.
func (c *schemaColumnsCache) tableColumns(ctx context.Context, query unsafeQuery, database, schema, table string) ([]snowflakeColumnRow, error) {
	m := c.memo(database, schema)
	m.once.Do(func() {
		stmt := "SHOW COLUMNS IN SCHEMA " + quoteIdentifier(database) + "." + quoteIdentifier(schema)
		rows, err := query(ctx, stmt)
		if err != nil {
			m.err = columnsAccessError(err, database, schema)
			return
		}
		byTable, err := decodeColumnRows(rows)
		if err != nil {
			m.err = err
			return
		}
		m.value = &schemaColumns{byTable: byTable, truncated: len(rows) >= showColumnsCap}
	})
	if m.err != nil {
		return nil, m.err
	}
	if !m.value.truncated {
		return m.value.byTable[table], nil
	}

	stmt := "SHOW COLUMNS IN TABLE " + quoteIdentifier(database) + "." + quoteIdentifier(schema) + "." + quoteIdentifier(table)
	rows, err := query(ctx, stmt)
	if err != nil {
		return nil, columnsAccessError(err, database, schema)
	}
	byTable, err := decodeColumnRows(rows)
	if err != nil {
		return nil, err
	}
	return byTable[table], nil
}

func (r *mqlSnowflakeTable) columns() ([]any, error) {
	account, err := snowflakeAccount(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	rows, err := account.cachedSchemaColumns.tableColumns(context.Background(), conn.Client().QueryUnsafe,
		r.DatabaseName.Data, r.SchemaName.Data, r.Name.Data)
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(rows))
	for _, c := range rows {
		res, err := CreateResource(r.MqlRuntime, "snowflake.table.column", map[string]*llx.RawData{
			"__id":     llx.StringData(r.__id + "/column/" + c.name),
			"name":     llx.StringData(c.name),
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
