// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/databricks/databricks-sdk-go/service/catalog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

func newTablesTestRuntime() *plugin.Runtime {
	return &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
}

func TestNewMqlDatabricksTable(t *testing.T) {
	// Synthetic: shaped after the Unity Catalog tables API's TableInfo and
	// ColumnInfo; no live workspace was read for this change.
	runtime := newTablesTestRuntime()
	external, err := newMqlDatabricksTable(runtime, catalog.TableInfo{
		Name:             "customers",
		FullName:         "main.crm.customers",
		CatalogName:      "main",
		SchemaName:       "crm",
		Owner:            "data-eng",
		TableType:        catalog.TableTypeExternal,
		DataSourceFormat: catalog.DataSourceFormatDelta,
		StorageLocation:  "s3://bucket/crm/customers",
		Comment:          "customer master",
		Columns: []catalog.ColumnInfo{
			{Name: "id", TypeText: "bigint", TypeName: catalog.ColumnTypeNameLong, Position: 0},
			{Name: "balance", TypeText: "decimal(10,2)", TypeName: catalog.ColumnTypeNameDecimal, Position: 1, Nullable: true, Comment: "account balance"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "main.crm.customers", external.FullName.Data)
	assert.Equal(t, "customers", external.Name.Data)
	assert.Equal(t, "main", external.CatalogName.Data)
	assert.Equal(t, "crm", external.SchemaName.Data)
	assert.Equal(t, "data-eng", external.Owner.Data)
	assert.Equal(t, "EXTERNAL", external.TableType.Data)
	assert.Equal(t, "DELTA", external.DataSourceFormat.Data)
	assert.Equal(t, "s3://bucket/crm/customers", external.StorageLocation.Data)
	assert.Equal(t, "customer master", external.Comment.Data)
	assert.Equal(t, "databricks.table/main.crm.customers", external.MqlID())

	cols, err := external.columns()
	require.NoError(t, err)
	require.Len(t, cols, 2)
	id := cols[0].(*mqlDatabricksTableColumn)
	balance := cols[1].(*mqlDatabricksTableColumn)
	assert.Equal(t, "id", id.Name.Data)
	assert.False(t, id.Nullable.Data)
	assert.Equal(t, "", id.Comment.Data)
	assert.Equal(t, int64(0), id.Position.Data)
	assert.Equal(t, "decimal(10,2)", balance.TypeName.Data, "the declared type text, not the bare type")
	assert.True(t, balance.Nullable.Data)
	assert.Equal(t, "account balance", balance.Comment.Data)
	assert.Equal(t, int64(1), balance.Position.Data)
	assert.NotEqual(t, id.MqlID(), balance.MqlID())

	view, err := newMqlDatabricksTable(runtime, catalog.TableInfo{
		Name: "v_customers", CatalogName: "main", SchemaName: "crm", TableType: catalog.TableTypeView,
	})
	require.NoError(t, err)
	assert.Equal(t, "", view.DataSourceFormat.Data)
	assert.Equal(t, "", view.StorageLocation.Data)
	assert.Equal(t, "main.crm.v_customers", view.FullName.Data, "the full name is built when the API omits it")
}

func TestTableColumnIDsDistinctAcrossTables(t *testing.T) {
	// Synthetic: two tables with a column of the same name.
	runtime := newTablesTestRuntime()
	a, err := newMqlDatabricksTable(runtime, catalog.TableInfo{FullName: "main.crm.a", Columns: []catalog.ColumnInfo{{Name: "email"}}})
	require.NoError(t, err)
	b, err := newMqlDatabricksTable(runtime, catalog.TableInfo{FullName: "main.crm.b", Columns: []catalog.ColumnInfo{{Name: "email"}}})
	require.NoError(t, err)
	ac, err := a.columns()
	require.NoError(t, err)
	bc, err := b.columns()
	require.NoError(t, err)
	assert.NotSame(t, ac[0], bc[0])
	assert.NotEqual(t, ac[0].(*mqlDatabricksTableColumn).MqlID(), bc[0].(*mqlDatabricksTableColumn).MqlID())
}

// seedSchemaFunctions puts a schema with a fixed function list in the runtime
// cache, so mask resolution reads it without an API call.
func seedSchemaFunctions(t *testing.T, runtime *plugin.Runtime, catalogName, schemaName string, fns plugin.TValue[[]any]) {
	t.Helper()
	s, err := newMqlDatabricksSchema(runtime, catalog.SchemaInfo{
		Name: schemaName, CatalogName: catalogName, FullName: catalogName + "." + schemaName,
	})
	require.NoError(t, err)
	s.Functions = fns
}

func TestColumnMaskResolution(t *testing.T) {
	// Synthetic: a fixed function list for the mask's schema.
	runtime := newTablesTestRuntime()
	res, err := CreateResource(runtime, "databricks.function", functionFields(catalog.FunctionInfo{
		Name: "mask_card", FullName: "main.gov.mask_card", CatalogName: "main", SchemaName: "gov", FunctionId: "f1",
	}))
	require.NoError(t, err)
	maskCard := res.(*mqlDatabricksFunction)
	seedSchemaFunctions(t, runtime, "main", "gov", plugin.TValue[[]any]{Data: []any{maskCard}, State: plugin.StateIsSet})

	table, err := newMqlDatabricksTable(runtime, catalog.TableInfo{
		FullName: "main.crm.customers", CatalogName: "main", SchemaName: "crm",
		Columns: []catalog.ColumnInfo{
			{Name: "card", Mask: &catalog.ColumnMask{FunctionName: "main.gov.mask_card"}},
			{Name: "ssn"},
			{Name: "phone", Mask: &catalog.ColumnMask{FunctionName: "main.gov.mask_phone"}},
		},
	})
	require.NoError(t, err)
	cols, err := table.columns()
	require.NoError(t, err)
	require.Len(t, cols, 3)

	card := cols[0].(*mqlDatabricksTableColumn)
	fn, err := card.mask()
	require.NoError(t, err)
	assert.Same(t, maskCard, fn)

	ssn := cols[1].(*mqlDatabricksTableColumn)
	fn, err = ssn.mask()
	require.NoError(t, err)
	assert.Nil(t, fn)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, ssn.Mask.State)

	phone := cols[2].(*mqlDatabricksTableColumn)
	fn, err = phone.mask()
	require.NoError(t, err)
	assert.Nil(t, fn, "a mask function missing from the list reads null")
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, phone.Mask.State)
}

func TestColumnMaskUnreadableFunctionsIsAnError(t *testing.T) {
	// Synthetic: the mask's schema functions could not be read (null), so the
	// mask is unknown, not absent.
	runtime := newTablesTestRuntime()
	seedSchemaFunctions(t, runtime, "main", "gov", plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull})
	table, err := newMqlDatabricksTable(runtime, catalog.TableInfo{
		FullName: "main.crm.customers",
		Columns:  []catalog.ColumnInfo{{Name: "card", Mask: &catalog.ColumnMask{FunctionName: "main.gov.mask_card"}}},
	})
	require.NoError(t, err)
	cols, err := table.columns()
	require.NoError(t, err)
	_, err = cols[0].(*mqlDatabricksTableColumn).mask()
	assert.Error(t, err)
}

func TestSplitFunctionName(t *testing.T) {
	// Synthetic.
	c, s, n, ok := splitFunctionName("main.gov.mask_card")
	assert.True(t, ok)
	assert.Equal(t, []string{"main", "gov", "mask_card"}, []string{c, s, n})
	for _, bad := range []string{"", "mask_card", "gov.mask_card", "main..mask_card", ".gov.mask"} {
		_, _, _, ok := splitFunctionName(bad)
		assert.False(t, ok, bad)
	}
}
