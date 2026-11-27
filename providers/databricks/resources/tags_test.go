// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/databricks/databricks-sdk-go/apierr"
	"github.com/databricks/databricks-sdk-go/service/catalog"
	"github.com/databricks/databricks-sdk-go/service/sql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/databricks/connection"
	"go.mondoo.com/mql/utils/syncx"
)

// fakeStatements answers ExecuteStatement from a map keyed by information_schema
// view name, counting the statements it runs.
type fakeStatements struct {
	rows       map[string][][]string
	execErr    error
	status     *sql.StatementStatus
	chunks     map[int][][]string // extra chunks for every statement
	statements []string
}

func (f *fakeStatements) ExecuteStatement(_ context.Context, req sql.ExecuteStatementRequest) (*sql.StatementResponse, error) {
	f.statements = append(f.statements, req.Statement)
	if f.execErr != nil {
		return nil, f.execErr
	}
	status := f.status
	if status == nil {
		status = &sql.StatementStatus{State: sql.StatementStateSucceeded}
	}
	var data [][]string
	for view, rows := range f.rows {
		if strings.HasSuffix(req.Statement, ".information_schema."+view) {
			data = rows
		}
	}
	return &sql.StatementResponse{
		StatementId: "stmt",
		Status:      status,
		Manifest:    &sql.ResultManifest{TotalChunkCount: 1 + len(f.chunks)},
		Result:      &sql.ResultData{DataArray: data},
	}, nil
}

func (f *fakeStatements) GetStatementResultChunkN(_ context.Context, req sql.GetStatementResultChunkNRequest) (*sql.ResultData, error) {
	return &sql.ResultData{ChunkIndex: req.ChunkIndex, DataArray: f.chunks[req.ChunkIndex]}, nil
}

func TestFoldTagRows(t *testing.T) {
	// Synthetic: rows in the column order tagStatement selects; no live
	// workspace was read for this change.
	ct := newCatalogTags()
	require.NoError(t, foldTagRows(catalogTagsView, "main", [][]string{
		{"main", "owner", "data-eng"},
		{"other", "owner", "someone"},
	}, ct))
	require.NoError(t, foldTagRows(schemaTagsView, "main", [][]string{
		{"main", "crm", "domain", "sales"},
	}, ct))
	require.NoError(t, foldTagRows(tableTagsView, "main", [][]string{
		{"main", "crm", "customers", "pii", ""},
	}, ct))
	require.NoError(t, foldTagRows(columnTagsView, "MAIN", [][]string{
		{"main", "crm", "customers", "email", "pii", "email"},
		{"main", "crm", "customers", "email", "class", "confidential"},
		{"main", "CRM", "Customers", "Phone", "pii", "phone"},
	}, ct))

	assert.Equal(t, map[string]string{"owner": "data-eng"}, ct.catalog, "rows of another catalog are ignored")
	assert.Equal(t, map[string]string{"domain": "sales"}, ct.schemas["crm"])
	assert.Equal(t, map[string]string{"pii": ""}, ct.tables["crm.customers"], "a NULL value reads empty")
	assert.Equal(t, map[string]string{"pii": "email", "class": "confidential"}, ct.columns["crm.customers.email"])
	assert.Equal(t, map[string]string{"pii": "phone"}, ct.columns["crm.customers.phone"], "keys are folded to lower case")
	assert.Empty(t, tagMap(ct.columns["crm.customers.id"]), "a column with no tag reads {}")
	assert.NotNil(t, tagMap(ct.columns["crm.customers.id"]))

	err := foldTagRows(columnTagsView, "main", [][]string{{"main", "crm"}}, newCatalogTags())
	assert.True(t, errors.Is(err, llx.ErrMalformedData))
}

func TestQuoteIdent(t *testing.T) {
	// Synthetic.
	assert.Equal(t, "`main`", quoteIdent("main"))
	assert.Equal(t, "`we``ird`", quoteIdent("we`ird"))
	assert.Equal(t, "SELECT catalog_name, tag_name, tag_value FROM `a``b`.information_schema.catalog_tags",
		tagStatement(catalogTagsView, "a`b"))
}

// tagsTestRuntime returns a runtime whose connection carries the given options.
func tagsTestRuntime(options map[string]string) *plugin.Runtime {
	conn := &connection.DatabricksConnection{Conf: &inventory.Config{Options: options}}
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

func TestTagsWithoutWarehouseNotApplicable(t *testing.T) {
	// Synthetic: no warehouse-id option on the connection.
	runtime := tagsTestRuntime(map[string]string{})
	cat, err := newMqlDatabricksCatalog(runtime, catalog.CatalogInfo{Name: "main", FullName: "main"})
	require.NoError(t, err)
	schema, err := newMqlDatabricksSchema(runtime, catalog.SchemaInfo{Name: "crm", CatalogName: "main", FullName: "main.crm"})
	require.NoError(t, err)
	table, err := newMqlDatabricksTable(runtime, catalog.TableInfo{
		Name: "customers", CatalogName: "main", SchemaName: "crm", FullName: "main.crm.customers",
		Columns: []catalog.ColumnInfo{{Name: "email"}},
	})
	require.NoError(t, err)
	cols, err := table.columns()
	require.NoError(t, err)
	column := cols[0].(*mqlDatabricksTableColumn)

	for name, read := range map[string]func() (map[string]any, error){
		"catalog": cat.tags, "schema": schema.tags, "table": table.tags, "column": column.tags,
	} {
		tags, err := read()
		assert.Nil(t, tags, name+": never an empty map without a warehouse")
		assert.True(t, errors.Is(err, llx.ErrNotApplicable), name)
		assert.ErrorContains(t, err, "no SQL warehouse configured for tag reads", name)
	}
}

func TestCatalogTagsReadOncePerCatalog(t *testing.T) {
	// Synthetic: a fake statement client behind the per-catalog memo.
	fake := &fakeStatements{rows: map[string][][]string{
		"table_tags":  {{"main", "crm", "customers", "pii", ""}},
		"column_tags": {{"main", "crm", "customers", "email", "pii", "email"}},
		"schema_tags": {{"main", "crm", "domain", "sales"}},
	}}
	var memo tagMemo
	load := func(name string) (*catalogTags, error) {
		return memo.get(name, func() (*catalogTags, error) {
			return loadCatalogTags(context.Background(), fake, "wh1", name)
		})
	}

	for range 3 {
		ct, err := load("main")
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"pii": "email"}, ct.columns["crm.customers.email"])
	}
	_, err := load("MAIN")
	require.NoError(t, err)
	assert.Len(t, fake.statements, 4, "four statements for the first catalog, then none")

	_, err = load("other")
	require.NoError(t, err)
	assert.Len(t, fake.statements, 8, "a second catalog runs four more")
	assert.Contains(t, fake.statements, "SELECT catalog_name, schema_name, table_name, column_name, tag_name, tag_value FROM `other`.information_schema.column_tags")
}

func TestCatalogTagsReadAllChunks(t *testing.T) {
	// Synthetic: a result split over two chunks.
	fake := &fakeStatements{
		rows:   map[string][][]string{"column_tags": {{"main", "crm", "t", "a", "pii", "1"}}},
		chunks: map[int][][]string{1: {{"main", "crm", "t", "b", "pii", "2"}}},
	}
	rows, err := runTagStatement(context.Background(), fake, "wh1", tagStatement(columnTagsView, "main"))
	require.NoError(t, err)
	assert.Len(t, rows, 2)
}

func TestTagStatementErrors(t *testing.T) {
	// Synthetic: the API and statement outcomes the tag reads classify.
	stmt := tagStatement(catalogTagsView, "main")

	_, err := runTagStatement(context.Background(), &fakeStatements{execErr: &apierr.APIError{StatusCode: 403, Message: "denied"}}, "wh1", stmt)
	assert.True(t, errors.Is(err, llx.ErrForbidden), "403")
	var lerr *llx.Error
	require.True(t, errors.As(err, &lerr))
	assert.Contains(t, lerr.Permissions, "USE CATALOG")

	_, err = runTagStatement(context.Background(), &fakeStatements{status: &sql.StatementStatus{
		State: sql.StatementStateFailed, SqlState: "42501", Error: &sql.ServiceError{Message: "INSUFFICIENT_PERMISSIONS"},
	}}, "wh1", stmt)
	assert.True(t, errors.Is(err, llx.ErrForbidden), "failed for permissions")

	_, err = runTagStatement(context.Background(), &fakeStatements{execErr: &apierr.APIError{StatusCode: 404, Message: "warehouse not found"}}, "wh1", stmt)
	assert.True(t, errors.Is(err, llx.ErrNotApplicable), "missing warehouse")

	_, err = runTagStatement(context.Background(), &fakeStatements{status: &sql.StatementStatus{State: sql.StatementStateCanceled}}, "wh1", stmt)
	assert.True(t, errors.Is(err, llx.ErrTargetUnavailable), "cancelled after the wait")

	_, err = runTagStatement(context.Background(), &fakeStatements{status: &sql.StatementStatus{
		State: sql.StatementStateFailed, SqlState: "42P01", Error: &sql.ServiceError{Message: "TABLE_OR_VIEW_NOT_FOUND"},
	}}, "wh1", stmt)
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(err), "another failure stays unclassified")

	transport := errors.New("connection reset by peer")
	_, err = runTagStatement(context.Background(), &fakeStatements{execErr: transport}, "wh1", stmt)
	assert.ErrorIs(t, err, transport)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(err))
}

func TestTagMemoKeepsTheError(t *testing.T) {
	// Synthetic: a refused catalog is not asked again.
	var memo tagMemo
	calls := 0
	denied := llx.Forbidden(errors.New("denied"))
	for range 2 {
		_, err := memo.get("main", func() (*catalogTags, error) {
			calls++
			return nil, denied
		})
		assert.ErrorIs(t, err, denied)
	}
	assert.Equal(t, 1, calls)
}
