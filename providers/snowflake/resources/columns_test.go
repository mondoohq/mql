// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	gosnowflake "github.com/snowflakedb/gosnowflake/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// showColumnsRow builds the cell map QueryUnsafe returns for one SHOW COLUMNS
// row. Every cell arrives as a string.
//
// Synthetic: the cell names and the data_type document follow the Snowflake
// SHOW COLUMNS documentation. No live account was read for this change, so
// none of these rows is measured.
func showColumnsRow(table, column, dataType, null, comment string) map[string]*any {
	return grantRowCells(map[string]any{
		"table_name":    table,
		"schema_name":   "PUBLIC",
		"column_name":   column,
		"data_type":     dataType,
		"null?":         null,
		"default":       "",
		"kind":          "COLUMN",
		"expression":    "",
		"comment":       comment,
		"database_name": "SALES",
		"autoincrement": "",
	})
}

func TestDecodeShowColumnsRow(t *testing.T) {
	got, err := decodeShowColumnsRow(showColumnsRow("CUSTOMERS", "EMAIL",
		`{"type":"TEXT","length":16777216,"byteLength":16777216,"nullable":true,"fixed":false}`, "true", "login address"))
	require.NoError(t, err)
	assert.Equal(t, snowflakeColumnRow{table: "CUSTOMERS", name: "EMAIL", typeName: "VARCHAR(16777216)", nullable: true, comment: "login address"}, got)

	got, err = decodeShowColumnsRow(showColumnsRow("CUSTOMERS", "ID",
		`{"type":"FIXED","precision":38,"scale":0,"nullable":false}`, "false", ""))
	require.NoError(t, err)
	assert.Equal(t, snowflakeColumnRow{table: "CUSTOMERS", name: "ID", typeName: "NUMBER(38,0)", nullable: false}, got)

	// The JSON's nullable wins over the null? cell; the cell is the fallback.
	got, err = decodeShowColumnsRow(showColumnsRow("T", "C", `{"type":"BOOLEAN"}`, "true", ""))
	require.NoError(t, err)
	assert.True(t, got.nullable)
	assert.Equal(t, "BOOLEAN", got.typeName)
}

func TestDecodeShowColumnsRowMalformedDataType(t *testing.T) {
	_, err := decodeShowColumnsRow(showColumnsRow("T", "C", "VARCHAR(10)", "true", ""))
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrMalformedData), "want MalformedData, got %v", err)
}

func TestFormatSnowflakeType(t *testing.T) {
	cases := map[string]string{
		`{"type":"TEXT","length":16777216}`:                "VARCHAR(16777216)",
		`{"type":"TEXT"}`:                                  "VARCHAR",
		`{"type":"FIXED","precision":10,"scale":2}`:        "NUMBER(10,2)",
		`{"type":"REAL"}`:                                  "FLOAT",
		`{"type":"BINARY","length":8388608}`:               "BINARY(8388608)",
		`{"type":"TIMESTAMP_NTZ","precision":0,"scale":9}`: "TIMESTAMP_NTZ(9)",
		`{"type":"TIME","precision":0,"scale":9}`:          "TIME(9)",
		`{"type":"DATE"}`:                                  "DATE",
		`{"type":"VARIANT"}`:                               "VARIANT",
		`{"type":"OBJECT"}`:                                "OBJECT",
	}
	for in, want := range cases {
		var dataType map[string]any
		require.NoError(t, json.Unmarshal([]byte(in), &dataType))
		assert.Equal(t, want, formatSnowflakeType(dataType), in)
	}
}

// countingQuery answers SHOW COLUMNS statements from a fixed set of rows per
// statement and counts the statements it ran.
type countingQuery struct {
	lock    sync.Mutex
	answers map[string][]map[string]*any
	err     error
	ran     []string
}

func (q *countingQuery) query(_ context.Context, stmt string) ([]map[string]*any, error) {
	q.lock.Lock()
	defer q.lock.Unlock()
	q.ran = append(q.ran, stmt)
	if q.err != nil {
		return nil, q.err
	}
	rows, ok := q.answers[stmt]
	if !ok {
		return nil, fmt.Errorf("unexpected statement %q", stmt)
	}
	return rows, nil
}

func TestSchemaColumnsOnePerSchema(t *testing.T) {
	// Synthetic: two tables of one schema, read concurrently, share one
	// statement; a second schema adds one.
	q := &countingQuery{answers: map[string][]map[string]*any{
		`SHOW COLUMNS IN SCHEMA "SALES"."PUBLIC"`: {
			showColumnsRow("CUSTOMERS", "ID", `{"type":"FIXED","precision":38,"scale":0,"nullable":false}`, "false", ""),
			showColumnsRow("CUSTOMERS", "EMAIL", `{"type":"TEXT","length":255,"nullable":true}`, "true", ""),
			showColumnsRow("ORDERS", "ORDER_ID", `{"type":"FIXED","precision":38,"scale":0,"nullable":false}`, "false", ""),
			// a view's columns are listed too and stay under the view's name
			showColumnsRow("CUSTOMER_EMAILS", "EMAIL", `{"type":"TEXT","length":255,"nullable":true}`, "true", ""),
		},
		`SHOW COLUMNS IN SCHEMA "SALES"."STAGING"`: {
			showColumnsRow("RAW", "PAYLOAD", `{"type":"VARIANT","nullable":true}`, "true", ""),
		},
	}}
	cache := &schemaColumnsCache{}
	ctx := context.Background()

	var wg sync.WaitGroup
	for _, table := range []string{"CUSTOMERS", "ORDERS", "CUSTOMERS", "ORDERS"} {
		wg.Go(func() {
			rows, err := cache.tableColumns(ctx, q.query, "SALES", "PUBLIC", table)
			assert.NoError(t, err)
			assert.NotEmpty(t, rows)
		})
	}
	wg.Wait()
	assert.Len(t, q.ran, 1)

	rows, err := cache.tableColumns(ctx, q.query, "SALES", "PUBLIC", "CUSTOMERS")
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, []string{"ID", "EMAIL"}, []string{rows[0].name, rows[1].name})

	// A table dropped between SHOW TABLES and SHOW COLUMNS has no columns.
	rows, err = cache.tableColumns(ctx, q.query, "SALES", "PUBLIC", "GONE")
	require.NoError(t, err)
	assert.Empty(t, rows)

	_, err = cache.tableColumns(ctx, q.query, "SALES", "STAGING", "RAW")
	require.NoError(t, err)
	assert.Len(t, q.ran, 2)
}

func TestShowColumnsCapFallback(t *testing.T) {
	// Synthetic: a schema answer of showColumnsCap rows may be cut, so each
	// table read falls back to SHOW COLUMNS IN TABLE.
	full := make([]map[string]*any, 0, showColumnsCap)
	for i := range showColumnsCap {
		full = append(full, showColumnsRow(fmt.Sprintf("T%d", i/10), fmt.Sprintf("C%d", i%10), `{"type":"DATE","nullable":true}`, "true", ""))
	}
	q := &countingQuery{answers: map[string][]map[string]*any{
		`SHOW COLUMNS IN SCHEMA "SALES"."BIG"`: full,
		`SHOW COLUMNS IN TABLE "SALES"."BIG"."LAST"`: {
			showColumnsRow("LAST", "ID", `{"type":"FIXED","precision":38,"scale":0,"nullable":false}`, "false", ""),
		},
		`SHOW COLUMNS IN TABLE "SALES"."BIG"."T0"`: full[:10],
	}}
	cache := &schemaColumnsCache{}
	ctx := context.Background()

	rows, err := cache.tableColumns(ctx, q.query, "SALES", "BIG", "LAST")
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "NUMBER(38,0)", rows[0].typeName)

	rows, err = cache.tableColumns(ctx, q.query, "SALES", "BIG", "T0")
	require.NoError(t, err)
	assert.Len(t, rows, 10)

	assert.Equal(t, []string{
		`SHOW COLUMNS IN SCHEMA "SALES"."BIG"`,
		`SHOW COLUMNS IN TABLE "SALES"."BIG"."LAST"`,
		`SHOW COLUMNS IN TABLE "SALES"."BIG"."T0"`,
	}, q.ran)
}

func TestSnowflakeColumnsDeniedIsForbidden(t *testing.T) {
	// Synthetic: SQLSTATE 42501 is how Snowflake reports a refused statement
	// (errors.go); no live account refused SHOW COLUMNS for this change.
	q := &countingQuery{err: &gosnowflake.SnowflakeError{Number: 3001, SQLState: "42501", Message: "SQL access control error"}}
	cache := &schemaColumnsCache{}
	ctx := context.Background()

	rows, err := cache.tableColumns(ctx, q.query, "SALES", "PUBLIC", "CUSTOMERS")
	require.Error(t, err)
	assert.Nil(t, rows, "a refusal is never an empty list")
	assert.True(t, errors.Is(err, llx.ErrForbidden), "want Forbidden, got %v", err)
	assert.Equal(t, []string{"USAGE ON SCHEMA SALES.PUBLIC"}, llx.ErrorDetailOf(err).Permissions)

	// The refusal is memoized: the second table does not ask again.
	_, err = cache.tableColumns(ctx, q.query, "SALES", "PUBLIC", "ORDERS")
	assert.True(t, errors.Is(err, llx.ErrForbidden))
	assert.Len(t, q.ran, 1)

	// A transport failure is not a refusal.
	boom := errors.New("dial tcp: i/o timeout")
	_, err = (&schemaColumnsCache{}).tableColumns(ctx, (&countingQuery{err: boom}).query, "SALES", "PUBLIC", "CUSTOMERS")
	assert.Same(t, boom, err)
}

func TestShowColumnsQuotesIdentifiers(t *testing.T) {
	// Synthetic: a quote in a name is doubled, so it cannot end the identifier.
	q := &countingQuery{answers: map[string][]map[string]*any{
		`SHOW COLUMNS IN SCHEMA "my""db"."a.b"`: {},
	}}
	_, err := (&schemaColumnsCache{}).tableColumns(context.Background(), q.query, `my"db`, "a.b", "T")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(q.ran[0], "SHOW COLUMNS IN SCHEMA "))
}
