// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	gosnowflake "github.com/snowflakedb/gosnowflake/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

// cell builds one QueryUnsafe cell; nil stands for SQL NULL.
func cell(v any) *any {
	if v == nil {
		return nil
	}
	return &v
}

// tagRefRow builds a TAG_REFERENCES row the way QueryUnsafe hands it back.
func tagRefRow(tagDB, tagSchema, tagName string, value any, domain, objDB, objSchema, objName string, column any) map[string]*any {
	return map[string]*any{
		"TAG_DATABASE":    cell(tagDB),
		"TAG_SCHEMA":      cell(tagSchema),
		"TAG_NAME":        cell(tagName),
		"TAG_VALUE":       cell(value),
		"DOMAIN":          cell(domain),
		"OBJECT_DATABASE": cell(objDB),
		"OBJECT_SCHEMA":   cell(objSchema),
		"OBJECT_NAME":     cell(objName),
		"COLUMN_NAME":     cell(column),
	}
}

// tagRefTestAccount returns a runtime whose account answers TAG_REFERENCES with
// rows (or err), counting the statements it runs.
func tagRefTestAccount(t *testing.T, rows []map[string]*any, err error) (*mqlSnowflakeAccount, *int32) {
	t.Helper()
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	account, aerr := snowflakeAccount(runtime)
	require.NoError(t, aerr)
	var calls int32
	account.tagReferenceIndex.query = func(_ context.Context, statement string) ([]map[string]*any, error) {
		atomic.AddInt32(&calls, 1)
		assert.Equal(t, tagReferencesQuery, statement)
		return rows, err
	}
	return account, &calls
}

func newTestTable(t *testing.T, runtime *plugin.Runtime, db, schema, name string) *mqlSnowflakeTable {
	t.Helper()
	table, err := newMqlSnowflakeTable(runtime, sdk.Table{DatabaseName: db, SchemaName: schema, Name: name})
	require.NoError(t, err)
	return table
}

func newTestTag(t *testing.T, runtime *plugin.Runtime, db, schema, name string) *mqlSnowflakeTag {
	t.Helper()
	tag, err := newMqlSnowflakeTag(runtime, sdk.Tag{DatabaseName: db, SchemaName: schema, Name: name})
	require.NoError(t, err)
	return tag
}

func TestDecodeTagReferenceRow(t *testing.T) {
	// Synthetic: rows shaped like the documented TAG_REFERENCES columns; no live
	// account was read for this change.
	t.Run("column row", func(t *testing.T) {
		r, ok := decodeTagReferenceRow(tagRefRow("GOV", "TAGS", "PII", "email", "COLUMN", "CRM", "PUBLIC", "CUSTOMERS", "EMAIL"))
		require.True(t, ok)
		assert.Equal(t, tagReferenceRow{
			tagDatabase: "GOV", tagSchema: "TAGS", tagName: "PII", value: "email", domain: "COLUMN",
			objectDatabase: "CRM", objectSchema: "PUBLIC", objectName: "CUSTOMERS", columnName: "EMAIL",
		}, r)
		assert.Equal(t, "GOV.TAGS.PII", r.tagQualifiedName())
		assert.Equal(t, "CRM.PUBLIC.CUSTOMERS", r.objectQualifiedName())
	})
	t.Run("table row with NULL column", func(t *testing.T) {
		r, ok := decodeTagReferenceRow(tagRefRow("GOV", "TAGS", "OWNER", "sales", "TABLE", "CRM", "PUBLIC", "CUSTOMERS", nil))
		require.True(t, ok)
		assert.Equal(t, "", r.columnName)
		assert.Equal(t, "TABLE", r.domain)
	})
	t.Run("NULL value reads empty", func(t *testing.T) {
		r, ok := decodeTagReferenceRow(tagRefRow("GOV", "TAGS", "PII", nil, "column", "CRM", "PUBLIC", "CUSTOMERS", "SSN"))
		require.True(t, ok)
		assert.Equal(t, "", r.value)
		assert.Equal(t, "COLUMN", r.domain, "the domain is folded to upper case")
	})
	t.Run("warehouse row has a bare qualified name", func(t *testing.T) {
		r, ok := decodeTagReferenceRow(tagRefRow("GOV", "TAGS", "COST", "x", "WAREHOUSE", "", "", "COMPUTE_WH", nil))
		require.True(t, ok)
		assert.Equal(t, "COMPUTE_WH", r.objectQualifiedName())
	})
	t.Run("row without tag name is skipped", func(t *testing.T) {
		_, ok := decodeTagReferenceRow(tagRefRow("GOV", "TAGS", "", "x", "TABLE", "CRM", "PUBLIC", "T", nil))
		assert.False(t, ok)
	})
	t.Run("row without domain is skipped", func(t *testing.T) {
		_, ok := decodeTagReferenceRow(tagRefRow("GOV", "TAGS", "PII", "x", "", "CRM", "PUBLIC", "T", nil))
		assert.False(t, ok)
	})
}

func TestTagReferenceIDDistinguishesTagsAndColumns(t *testing.T) {
	// Synthetic: two tags on one column, and one tag on two columns.
	base := tagReferenceRow{tagDatabase: "GOV", tagSchema: "TAGS", tagName: "PII", domain: "COLUMN",
		objectDatabase: "CRM", objectSchema: "PUBLIC", objectName: "CUSTOMERS", columnName: "EMAIL"}
	otherTag := base
	otherTag.tagName = "SENSITIVITY"
	otherColumn := base
	otherColumn.columnName = "PHONE"
	otherBoth := otherColumn
	otherBoth.tagName = "SENSITIVITY"

	ids := map[string]bool{}
	for _, r := range []tagReferenceRow{base, otherTag, otherColumn, otherBoth} {
		ids[tagReferenceID(r)] = true
	}
	assert.Len(t, ids, 4)
	assert.Equal(t, "COLUMN/CRM.PUBLIC.CUSTOMERS/EMAIL/GOV.TAGS.PII", tagReferenceID(base))
}

func TestTagReferencesQueriedOncePerAccount(t *testing.T) {
	// Synthetic: two tables and a tag read their references; one statement.
	account, calls := tagRefTestAccount(t, []map[string]*any{
		tagRefRow("GOV", "TAGS", "PII", "email", "COLUMN", "CRM", "PUBLIC", "CUSTOMERS", "EMAIL"),
		tagRefRow("GOV", "TAGS", "PII", "", "TABLE", "CRM", "PUBLIC", "ORDERS", nil),
	}, nil)
	runtime := account.MqlRuntime

	customers := newTestTable(t, runtime, "CRM", "PUBLIC", "CUSTOMERS")
	orders := newTestTable(t, runtime, "CRM", "PUBLIC", "ORDERS")
	pii := newTestTag(t, runtime, "GOV", "TAGS", "PII")

	c, err := customers.tagReferences()
	require.NoError(t, err)
	o, err := orders.tagReferences()
	require.NoError(t, err)
	p, err := pii.references()
	require.NoError(t, err)
	all, err := account.tagReferences()
	require.NoError(t, err)

	assert.Len(t, c, 1)
	assert.Len(t, o, 1)
	assert.Len(t, p, 2)
	assert.Len(t, all, 2)
	assert.Equal(t, int32(1), atomic.LoadInt32(calls))
}

func TestTableTagReferencesMatchByStoredName(t *testing.T) {
	// Synthetic: neighbours that share a prefix or a table name in another
	// schema must not be matched.
	account, _ := tagRefTestAccount(t, []map[string]*any{
		tagRefRow("GOV", "TAGS", "PII", "", "TABLE", "CRM", "PUBLIC", "CUSTOMERS", nil),
		tagRefRow("GOV", "TAGS", "PII", "email", "COLUMN", "CRM", "PUBLIC", "CUSTOMERS", "EMAIL"),
		tagRefRow("GOV", "TAGS", "PII", "", "TABLE", "CRM", "PUBLIC", "CUSTOMERS2", nil),
		tagRefRow("GOV", "TAGS", "PII", "", "TABLE", "CRM", "STAGING", "CUSTOMERS", nil),
		tagRefRow("GOV", "TAGS", "PII", "", "SCHEMA", "CRM", "PUBLIC", "", nil),
		tagRefRow("GOV", "TAGS", "PII", "", "TABLE", "CRM", "PUBLIC", "customers", nil),
	}, nil)
	customers := newTestTable(t, account.MqlRuntime, "CRM", "PUBLIC", "CUSTOMERS")

	refs, err := customers.tagReferences()
	require.NoError(t, err)
	require.Len(t, refs, 2)
	cols := []string{}
	for _, r := range refs {
		cols = append(cols, r.(*mqlSnowflakeTagReference).ColumnName.Data)
	}
	assert.ElementsMatch(t, []string{"", "EMAIL"}, cols)
}

func seedDatabaseAndSchemaIndexes(account *mqlSnowflakeAccount, dbs []sdk.Database, schemas []sdk.Schema) {
	account.cachedDatabaseIndex.get(func() (map[string]sdk.Database, error) { return buildDatabaseIndex(dbs), nil })
	account.cachedSchemaIndex.get(func() (map[string]sdk.Schema, error) { return buildSchemaIndex(schemas), nil })
}

func loadOneRef(t *testing.T, account *mqlSnowflakeAccount, i int) *mqlSnowflakeTagReference {
	t.Helper()
	refs, err := account.loadTagReferences()
	require.NoError(t, err)
	return refs[i]
}

func TestTagReferenceDatabaseAndSchemaAccessors(t *testing.T) {
	// Synthetic: fixed database and schema listings.
	account, _ := tagRefTestAccount(t, []map[string]*any{
		tagRefRow("GOV", "TAGS", "PII", "email", "COLUMN", "CRM", "PUBLIC", "CUSTOMERS", "EMAIL"),
		tagRefRow("GOV", "TAGS", "COST", "x", "WAREHOUSE", "", "", "COMPUTE_WH", nil),
		tagRefRow("GOV", "TAGS", "PII", "", "TABLE", "HIDDEN", "PUBLIC", "T", nil),
		tagRefRow("GOV", "TAGS", "PII", "", "DATABASE", "", "", "CRM", nil),
	}, nil)
	seedDatabaseAndSchemaIndexes(account,
		[]sdk.Database{{Name: "CRM"}, {Name: "GOV"}},
		[]sdk.Schema{{DatabaseName: "CRM", Name: "PUBLIC"}, {DatabaseName: "GOV", Name: "TAGS"}})

	column := loadOneRef(t, account, 0)
	db, err := column.objectDatabase()
	require.NoError(t, err)
	require.NotNil(t, db)
	assert.Equal(t, "CRM", db.Name.Data)
	schema, err := column.objectSchema()
	require.NoError(t, err)
	require.NotNil(t, schema)
	assert.Equal(t, "PUBLIC", schema.Name.Data)
	assert.Equal(t, "CRM", schema.DatabaseName.Data)
	tagDB, err := column.tagDatabase()
	require.NoError(t, err)
	require.NotNil(t, tagDB)
	assert.Equal(t, "GOV", tagDB.Name.Data)
	tagSchema, err := column.tagSchema()
	require.NoError(t, err)
	require.NotNil(t, tagSchema)
	assert.Equal(t, "TAGS", tagSchema.Name.Data)

	warehouse := loadOneRef(t, account, 1)
	db, err = warehouse.objectDatabase()
	require.NoError(t, err)
	assert.Nil(t, db)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, warehouse.ObjectDatabase.State)
	schema, err = warehouse.objectSchema()
	require.NoError(t, err)
	assert.Nil(t, schema)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, warehouse.ObjectSchema.State)
	assert.Equal(t, "COMPUTE_WH", warehouse.ObjectQualifiedName.Data)

	unlisted := loadOneRef(t, account, 2)
	db, err = unlisted.objectDatabase()
	require.NoError(t, err)
	assert.Nil(t, db)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, unlisted.ObjectDatabase.State)
	assert.Equal(t, "HIDDEN.PUBLIC.T", unlisted.ObjectQualifiedName.Data)

	database := loadOneRef(t, account, 3)
	db, err = database.objectDatabase()
	require.NoError(t, err)
	require.NotNil(t, db, "a DATABASE row names its database in OBJECT_NAME")
	assert.Equal(t, "CRM", db.Name.Data)
	schema, err = database.objectSchema()
	require.NoError(t, err)
	assert.Nil(t, schema)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, database.ObjectSchema.State)
}

func TestTagReferenceDatabaseListingErrorIsReturned(t *testing.T) {
	// Synthetic: a failed database listing is an error, not a null.
	account, _ := tagRefTestAccount(t, []map[string]*any{
		tagRefRow("GOV", "TAGS", "PII", "email", "COLUMN", "CRM", "PUBLIC", "CUSTOMERS", "EMAIL"),
	}, nil)
	listErr := errors.New("connection reset")
	account.cachedDatabaseIndex.get(func() (map[string]sdk.Database, error) { return nil, listErr })
	ref := loadOneRef(t, account, 0)
	_, err := ref.objectDatabase()
	assert.ErrorIs(t, err, listErr)
}

func TestTagReferenceTableAndTagResolution(t *testing.T) {
	// Synthetic: fixed table and tag listings.
	account, _ := tagRefTestAccount(t, []map[string]*any{
		tagRefRow("GOV", "TAGS", "PII", "email", "COLUMN", "CRM", "PUBLIC", "CUSTOMERS", "EMAIL"),
		tagRefRow("GOV", "TAGS", "PII", "", "TABLE", "CRM", "PUBLIC", "DROPPED", nil),
		tagRefRow("GOV", "TAGS", "GONE", "x", "WAREHOUSE", "", "", "COMPUTE_WH", nil),
	}, nil)
	runtime := account.MqlRuntime
	customers := newTestTable(t, runtime, "CRM", "PUBLIC", "CUSTOMERS")
	pii := newTestTag(t, runtime, "GOV", "TAGS", "PII")
	account.Tables = plugin.TValue[[]any]{Data: []any{customers}, State: plugin.StateIsSet}
	account.Tags = plugin.TValue[[]any]{Data: []any{pii}, State: plugin.StateIsSet}

	column := loadOneRef(t, account, 0)
	table, err := column.table()
	require.NoError(t, err)
	assert.Same(t, customers, table)
	tag, err := column.tag()
	require.NoError(t, err)
	assert.Same(t, pii, tag)

	dropped := loadOneRef(t, account, 1)
	table, err = dropped.table()
	require.NoError(t, err)
	assert.Nil(t, table)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, dropped.Table.State)

	warehouse := loadOneRef(t, account, 2)
	table, err = warehouse.table()
	require.NoError(t, err)
	assert.Nil(t, table)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, warehouse.Table.State)
	tag, err = warehouse.tag()
	require.NoError(t, err)
	assert.Nil(t, tag, "a tag not in the listing reads null")
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, warehouse.Tag.State)
}

func TestTagReferencesDeniedIsForbidden(t *testing.T) {
	// Synthetic: SQLSTATE 42501 as the driver reports it for a refused read.
	denied := &gosnowflake.SnowflakeError{Number: 3001, SQLState: "42501", Message: "SQL access control error"}
	account, calls := tagRefTestAccount(t, nil, denied)
	runtime := account.MqlRuntime
	customers := newTestTable(t, runtime, "CRM", "PUBLIC", "CUSTOMERS")
	pii := newTestTag(t, runtime, "GOV", "TAGS", "PII")

	check := func(name string, refs []any, err error) {
		t.Helper()
		require.Error(t, err, name)
		assert.Nil(t, refs, name+": a refused read is never an empty list")
		assert.True(t, errors.Is(err, llx.ErrForbidden), name)
		var lerr *llx.Error
		require.True(t, errors.As(err, &lerr), name)
		assert.Contains(t, lerr.Permissions, accountUsagePrivilege, name)
	}
	refs, err := account.tagReferences()
	check("account", refs, err)
	refs, err = customers.tagReferences()
	check("table", refs, err)
	refs, err = pii.references()
	check("tag", refs, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(calls), "the error is memoized")
}

func TestTagReferencesEmptyAccountIsEmptyList(t *testing.T) {
	// Synthetic: a successful read with no rows means nothing is set.
	account, _ := tagRefTestAccount(t, []map[string]*any{}, nil)
	refs, err := account.tagReferences()
	require.NoError(t, err)
	assert.NotNil(t, refs)
	assert.Empty(t, refs)
}
