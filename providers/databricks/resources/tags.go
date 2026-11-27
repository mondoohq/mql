// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/databricks/databricks-sdk-go/service/sql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/databricks/connection"
)

// Governed tags on Unity Catalog catalogs, schemas, tables and columns.
//
// Tags are read from the information_schema views of each catalog through a SQL
// warehouse: four statements per catalog, run once per scan the first time a
// tag field of that catalog is read. The per-object tag API would cost one call
// per catalog, schema, table and column instead.
//
// Only information_schema views are selected; no row of a user table is read.
// The catalog name is the only caller-controlled text in a statement, and it is
// backtick-quoted.

// errNoWarehouse is returned, as NotApplicable, by every tag field when the
// connection names no SQL warehouse.
var errNoWarehouse = errors.New("no SQL warehouse configured for tag reads")

// tagStatementWait is how long one statement may wait for its result. A
// statement still running after it is cancelled and reported as unavailable.
const tagStatementWait = "30s"

// tagReadPermissions are the privileges a role needs to read the tag views.
var tagReadPermissions = []string{"CAN USE on the SQL warehouse", "USE CATALOG", "SELECT on information_schema"}

// sqlStateInsufficientPrivilege is the SQLSTATE Databricks reports for a
// statement refused for lack of privilege (from the Databricks error
// reference, not measured).
const sqlStateInsufficientPrivilege = "42501"

// tagView is one of the four information_schema tag views.
type tagView int

const (
	catalogTagsView tagView = iota
	schemaTagsView
	tableTagsView
	columnTagsView
)

var tagViews = []tagView{catalogTagsView, schemaTagsView, tableTagsView, columnTagsView}

// name is the view's name in information_schema.
func (v tagView) name() string {
	switch v {
	case catalogTagsView:
		return "catalog_tags"
	case schemaTagsView:
		return "schema_tags"
	case tableTagsView:
		return "table_tags"
	default:
		return "column_tags"
	}
}

// columns are the selected columns, in the order foldTagRows reads them. Each
// view's last two columns are tag_name and tag_value.
func (v tagView) columns() []string {
	switch v {
	case catalogTagsView:
		return []string{"catalog_name", "tag_name", "tag_value"}
	case schemaTagsView:
		return []string{"catalog_name", "schema_name", "tag_name", "tag_value"}
	case tableTagsView:
		return []string{"catalog_name", "schema_name", "table_name", "tag_name", "tag_value"}
	default:
		return []string{"catalog_name", "schema_name", "table_name", "column_name", "tag_name", "tag_value"}
	}
}

// quoteIdent backtick-quotes a Unity Catalog identifier, doubling backticks.
func quoteIdent(s string) string {
	return "`" + strings.ReplaceAll(s, "`", "``") + "`"
}

// tagStatement is the statement that reads one view of one catalog.
func tagStatement(view tagView, catalogName string) string {
	return "SELECT " + strings.Join(view.columns(), ", ") +
		" FROM " + quoteIdent(catalogName) + ".information_schema." + view.name()
}

// catalogTags holds the four tag views of one catalog. Keys are lower case:
// Unity Catalog identifiers are case-insensitive and stored lower case.
type catalogTags struct {
	catalog map[string]string            // tag -> value
	schemas map[string]map[string]string // schema -> tag -> value
	tables  map[string]map[string]string // "schema.table" -> tag -> value
	columns map[string]map[string]string // "schema.table.column" -> tag -> value
}

func newCatalogTags() *catalogTags {
	return &catalogTags{
		catalog: map[string]string{},
		schemas: map[string]map[string]string{},
		tables:  map[string]map[string]string{},
		columns: map[string]map[string]string{},
	}
}

func tagKey(parts ...string) string {
	return strings.ToLower(strings.Join(parts, "."))
}

func setTag(m map[string]map[string]string, key, tag, value string) {
	inner, ok := m[key]
	if !ok {
		inner = map[string]string{}
		m[key] = inner
	}
	inner[tag] = value
}

// foldTagRows folds the rows of one view of catalogName into ct. A NULL tag
// value arrives as an empty string and stays one. Rows of another catalog are
// ignored. A row shorter than the view's column list is malformed.
func foldTagRows(view tagView, catalogName string, rows [][]string, ct *catalogTags) error {
	want := len(view.columns())
	for i, row := range rows {
		if len(row) < want {
			return llx.MalformedData(fmt.Errorf("databricks %s row %d has %d columns, want %d", view.name(), i, len(row), want))
		}
		if !strings.EqualFold(row[0], catalogName) {
			continue
		}
		tag, value := row[want-2], row[want-1]
		if tag == "" {
			continue
		}
		switch view {
		case catalogTagsView:
			ct.catalog[tag] = value
		case schemaTagsView:
			setTag(ct.schemas, tagKey(row[1]), tag, value)
		case tableTagsView:
			setTag(ct.tables, tagKey(row[1], row[2]), tag, value)
		case columnTagsView:
			setTag(ct.columns, tagKey(row[1], row[2], row[3]), tag, value)
		}
	}
	return nil
}

// statementClient is the part of the Statement Execution API the tag reads use.
type statementClient interface {
	ExecuteStatement(ctx context.Context, request sql.ExecuteStatementRequest) (*sql.StatementResponse, error)
	GetStatementResultChunkN(ctx context.Context, request sql.GetStatementResultChunkNRequest) (*sql.ResultData, error)
}

// classifyTagReadError maps a failed tag statement call to its error kind. A
// 403 is Forbidden with the privileges named; the other statuses follow
// classifyDatabricksError, under which a 404 for a missing warehouse is
// NotApplicable.
func classifyTagReadError(err error) error {
	if code, ok := databricksStatusCode(err); ok && code == 403 {
		return llx.Forbidden(err, llx.WithPermissions(tagReadPermissions...))
	}
	return classifyDatabricksError(err)
}

// statementResultError turns a statement that did not succeed into an error.
func statementResultError(warehouseID, statement string, status *sql.StatementStatus) error {
	if status == nil {
		return fmt.Errorf("databricks statement on warehouse %s returned no status", warehouseID)
	}
	switch status.State {
	case sql.StatementStatePending, sql.StatementStateRunning, sql.StatementStateCanceled:
		return llx.Unavailable(fmt.Errorf("databricks statement did not finish within %s on SQL warehouse %s (state %s)",
			tagStatementWait, warehouseID, status.State))
	case sql.StatementStateFailed:
		msg := ""
		if status.Error != nil {
			msg = status.Error.Message
		}
		err := fmt.Errorf("databricks statement %q failed on SQL warehouse %s: %s", statement, warehouseID, msg)
		if status.SqlState == sqlStateInsufficientPrivilege {
			return llx.Forbidden(err, llx.WithPermissions(tagReadPermissions...))
		}
		return err
	}
	return fmt.Errorf("databricks statement on SQL warehouse %s ended in state %s", warehouseID, status.State)
}

// runTagStatement runs one statement and returns every row of every chunk.
func runTagStatement(ctx context.Context, client statementClient, warehouseID, statement string) ([][]string, error) {
	res, err := client.ExecuteStatement(ctx, sql.ExecuteStatementRequest{
		WarehouseId:   warehouseID,
		Statement:     statement,
		WaitTimeout:   tagStatementWait,
		OnWaitTimeout: sql.ExecuteStatementRequestOnWaitTimeoutCancel,
		Disposition:   sql.DispositionInline,
		Format:        sql.FormatJsonArray,
	})
	if err != nil {
		return nil, classifyTagReadError(err)
	}
	if res.Status == nil || res.Status.State != sql.StatementStateSucceeded {
		return nil, statementResultError(warehouseID, statement, res.Status)
	}
	if res.Manifest != nil && res.Manifest.Truncated {
		// A truncated result would under-report tags; never answer from it.
		return nil, fmt.Errorf("databricks statement %q on SQL warehouse %s returned a truncated result", statement, warehouseID)
	}

	rows := [][]string{}
	if res.Result != nil {
		rows = append(rows, res.Result.DataArray...)
	}
	chunks := 0
	if res.Manifest != nil {
		chunks = res.Manifest.TotalChunkCount
	}
	for i := 1; i < chunks; i++ {
		chunk, err := client.GetStatementResultChunkN(ctx, sql.GetStatementResultChunkNRequest{
			StatementId: res.StatementId,
			ChunkIndex:  i,
		})
		if err != nil {
			return nil, classifyTagReadError(err)
		}
		rows = append(rows, chunk.DataArray...)
	}
	return rows, nil
}

// loadCatalogTags runs the four statements for one catalog through the
// warehouse and folds them into catalogTags.
func loadCatalogTags(ctx context.Context, client statementClient, warehouseID, catalogName string) (*catalogTags, error) {
	ct := newCatalogTags()
	for _, view := range tagViews {
		stmt := tagStatement(view, catalogName)
		rows, err := runTagStatement(ctx, client, warehouseID, stmt)
		if err != nil {
			return nil, err
		}
		if err := foldTagRows(view, catalogName, rows, ct); err != nil {
			return nil, err
		}
	}
	return ct, nil
}

// catalogTagsEntry is one catalog's memoized read, value and error.
type catalogTagsEntry struct {
	once sync.Once
	tags *catalogTags
	err  error
}

// tagMemo memoizes catalogTags per catalog for the scan. A refused catalog is
// not asked again: its error is memoized with the value.
type tagMemo struct {
	mu        sync.Mutex
	byCatalog map[string]*catalogTagsEntry
}

func (m *tagMemo) get(catalogName string, load func() (*catalogTags, error)) (*catalogTags, error) {
	m.mu.Lock()
	if m.byCatalog == nil {
		m.byCatalog = map[string]*catalogTagsEntry{}
	}
	key := strings.ToLower(catalogName)
	entry, ok := m.byCatalog[key]
	if !ok {
		entry = &catalogTagsEntry{}
		m.byCatalog[key] = entry
	}
	m.mu.Unlock()

	entry.once.Do(func() {
		entry.tags, entry.err = load()
	})
	return entry.tags, entry.err
}

// tagsForCatalog returns the memoized tags of one catalog, reading them on the
// first call. Without a configured warehouse it returns NotApplicable.
func tagsForCatalog(runtime *plugin.Runtime, catalogName string) (*catalogTags, error) {
	conn := runtime.Connection.(*connection.DatabricksConnection)
	warehouseID := conn.WarehouseID()
	if warehouseID == "" {
		return nil, llx.NotApplicable(errNoWarehouse)
	}
	ws, err := workspaceClient(runtime)
	if err != nil {
		return nil, err
	}
	rootRes, err := NewResource(runtime, "databricks", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	root := rootRes.(*mqlDatabricks)
	return root.tagMemo.get(catalogName, func() (*catalogTags, error) {
		return loadCatalogTags(context.Background(), ws.StatementExecution, warehouseID, catalogName)
	})
}

// tagMap converts one level's tags to the field value; absent reads {}.
func tagMap(tags map[string]string) map[string]any {
	out := make(map[string]any, len(tags))
	for k, v := range tags {
		out[k] = v
	}
	return out
}

func (r *mqlDatabricksCatalog) tags() (map[string]any, error) {
	ct, err := tagsForCatalog(r.MqlRuntime, r.Name.Data)
	if err != nil {
		return nil, err
	}
	return tagMap(ct.catalog), nil
}

func (r *mqlDatabricksSchema) tags() (map[string]any, error) {
	ct, err := tagsForCatalog(r.MqlRuntime, r.CatalogName.Data)
	if err != nil {
		return nil, err
	}
	return tagMap(ct.schemas[tagKey(r.Name.Data)]), nil
}

func (r *mqlDatabricksTable) tags() (map[string]any, error) {
	ct, err := tagsForCatalog(r.MqlRuntime, r.CatalogName.Data)
	if err != nil {
		return nil, err
	}
	return tagMap(ct.tables[tagKey(r.SchemaName.Data, r.Name.Data)]), nil
}

func (r *mqlDatabricksTableColumn) tags() (map[string]any, error) {
	ct, err := tagsForCatalog(r.MqlRuntime, r.cacheCatalogName)
	if err != nil {
		return nil, err
	}
	return tagMap(ct.columns[tagKey(r.cacheSchemaName, r.cacheTableName, r.Name.Data)]), nil
}
