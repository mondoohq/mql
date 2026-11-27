// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"

	databricks "github.com/databricks/databricks-sdk-go"
	"github.com/databricks/databricks-sdk-go/service/catalog"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Unity Catalog tables and their columns.
//
// The tables list returns every table of a schema with its columns, so a
// table's columns cost no call of their own. Only metadata is read: names,
// types, comments and the mask function's name. No row of a table is selected.

type mqlDatabricksTableInternal struct {
	// cacheColumns are the columns the tables list returned; columns reads them.
	cacheColumns []catalog.ColumnInfo
}

type mqlDatabricksTableColumnInternal struct {
	// cacheMaskFunction is the fully qualified name of the column mask's
	// function, empty when the column has no mask.
	cacheMaskFunction string
}

// tablePageLimit bounds how many tables one schema may yield. It is a
// termination guard against a pagination cursor that never advances; exceeding
// it is an error rather than a silently truncated list.
const tablePageLimit = 100000

// listTables walks every page of a schema's Unity Catalog tables, columns
// included.
func listTables(ctx context.Context, ws *databricks.WorkspaceClient, catalogName, schemaName string) ([]catalog.TableInfo, error) {
	it := ws.Tables.List(ctx, catalog.ListTablesRequest{
		CatalogName: catalogName,
		SchemaName:  schemaName,
	})
	out := []catalog.TableInfo{}
	for it.HasNext(ctx) {
		t, err := it.Next(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
		if len(out) > tablePageLimit {
			return nil, fmt.Errorf(
				"databricks returned more than %d tables for schema %s.%s, which means its pagination cursor is not advancing",
				tablePageLimit, catalogName, schemaName)
		}
	}
	return out, nil
}

// tables lists the Unity Catalog tables and views in the schema.
func (r *mqlDatabricksSchema) tables() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	infos, err := listTables(context.Background(), ws, r.CatalogName.Data, r.Name.Data)
	if err != nil {
		return nil, classifyDatabricksError(err)
	}
	out := make([]any, 0, len(infos))
	for i := range infos {
		t, err := newMqlDatabricksTable(r.MqlRuntime, infos[i])
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// tableFullName is the table's fully qualified name, built from its parts when
// the API omits it.
func tableFullName(t catalog.TableInfo) string {
	if t.FullName != "" {
		return t.FullName
	}
	return t.CatalogName + "." + t.SchemaName + "." + t.Name
}

// tableFields maps one table record to its MQL fields.
func tableFields(t catalog.TableInfo) map[string]*llx.RawData {
	fullName := tableFullName(t)
	return map[string]*llx.RawData{
		"__id":             llx.StringData("databricks.table/" + fullName),
		"name":             llx.StringData(t.Name),
		"fullName":         llx.StringData(fullName),
		"catalogName":      llx.StringData(t.CatalogName),
		"schemaName":       llx.StringData(t.SchemaName),
		"owner":            llx.StringData(t.Owner),
		"tableType":        llx.StringData(string(t.TableType)),
		"dataSourceFormat": llx.StringData(string(t.DataSourceFormat)),
		"storageLocation":  llx.StringData(t.StorageLocation),
		"comment":          llx.StringData(t.Comment),
	}
}

func newMqlDatabricksTable(runtime *plugin.Runtime, t catalog.TableInfo) (*mqlDatabricksTable, error) {
	res, err := CreateResource(runtime, "databricks.table", tableFields(t))
	if err != nil {
		return nil, err
	}
	table := res.(*mqlDatabricksTable)
	table.cacheColumns = t.Columns
	return table, nil
}

// initDatabricksTable resolves a table by fullName, or by catalogName,
// schemaName and name, so a table can be selected directly.
func initDatabricksTable(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}
	str := func(key string) string {
		if raw, ok := args[key]; ok && raw != nil {
			s, _ := raw.Value.(string)
			return s
		}
		return ""
	}
	fullName := str("fullName")
	if fullName == "" {
		catalogName, schemaName, name := str("catalogName"), str("schemaName"), str("name")
		if catalogName == "" || schemaName == "" || name == "" {
			return nil, nil, fmt.Errorf("databricks.table requires a fullName, or a catalogName, schemaName and name")
		}
		fullName = catalogName + "." + schemaName + "." + name
	}

	ws, err := workspaceClient(runtime)
	if err != nil {
		return nil, nil, err
	}
	t, err := ws.Tables.GetByFullName(context.Background(), fullName)
	if err != nil {
		if code, ok := databricksStatusCode(err); ok && code == 404 {
			return nil, nil, fmt.Errorf("databricks.table %q not found: %w", fullName, err)
		}
		return nil, nil, classifyDatabricksError(err)
	}
	res, err := newMqlDatabricksTable(runtime, *t)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlDatabricksTable) catalog() (*mqlDatabricksCatalog, error) {
	if r.CatalogName.Data == "" {
		r.Catalog.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return databricksCatalogByName(r.MqlRuntime, r.CatalogName.Data)
}

// databricksCatalogByName returns the catalog resource for name, reusing one
// the scan already created. NewResource runs the catalog's init, a
// GetByName call, before it looks at the cache, so without this every table
// of a schema would fetch its catalog again.
func databricksCatalogByName(runtime *plugin.Runtime, name string) (*mqlDatabricksCatalog, error) {
	if cached, ok := runtime.Resources.Get("databricks.catalog\x00databricks.catalog/" + name); ok {
		if c, ok := cached.(*mqlDatabricksCatalog); ok {
			return c, nil
		}
	}
	c, err := NewResource(runtime, "databricks.catalog", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return c.(*mqlDatabricksCatalog), nil
}

func (r *mqlDatabricksTable) schema() (*mqlDatabricksSchema, error) {
	s, err := databricksSchemaByName(r.MqlRuntime, r.CatalogName.Data, r.SchemaName.Data)
	if err != nil {
		return nil, err
	}
	if s == nil {
		r.Schema.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return s, nil
}

// databricksSchemaByName returns the schema resource for catalog.schema,
// reusing one the scan already created before hydrating it through the
// schema's init. nil, nil means an empty name.
func databricksSchemaByName(runtime *plugin.Runtime, catalogName, schemaName string) (*mqlDatabricksSchema, error) {
	if catalogName == "" || schemaName == "" {
		return nil, nil
	}
	if cached, ok := runtime.Resources.Get("databricks.schema\x00databricks.schema/" + catalogName + "." + schemaName); ok {
		if s, ok := cached.(*mqlDatabricksSchema); ok {
			return s, nil
		}
	}
	s, err := NewResource(runtime, "databricks.schema", map[string]*llx.RawData{
		"catalogName": llx.StringData(catalogName),
		"name":        llx.StringData(schemaName),
	})
	if err != nil {
		return nil, err
	}
	return s.(*mqlDatabricksSchema), nil
}

// columnFields maps one column of a table to its MQL fields. typeName is the
// declared type text (decimal(10,2)), not the bare type enum (DECIMAL), so the
// precision and scale survive.
func columnFields(tableFullName string, c catalog.ColumnInfo) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":     llx.StringData("databricks.table.column/" + tableFullName + "/" + c.Name),
		"name":     llx.StringData(c.Name),
		"typeName": llx.StringData(c.TypeText),
		"position": llx.IntData(int64(c.Position)),
		"nullable": llx.BoolData(c.Nullable),
		"comment":  llx.StringData(c.Comment),
	}
}

// columnMaskFunction is the mask function's fully qualified name, empty when
// the column has no mask.
func columnMaskFunction(c catalog.ColumnInfo) string {
	if c.Mask == nil {
		return ""
	}
	return c.Mask.FunctionName
}

// columnInfos returns the table's columns. The tables list includes them unless
// omit_columns is set, which listTables does not set. A table that came back
// without columns is read once on its own, so a list response that omits them
// yields the columns at the cost of one call per such table rather than an
// empty list.
func (r *mqlDatabricksTable) columnInfos() ([]catalog.ColumnInfo, error) {
	if len(r.cacheColumns) > 0 {
		return r.cacheColumns, nil
	}
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	t, err := ws.Tables.GetByFullName(context.Background(), r.FullName.Data)
	if err != nil {
		return nil, classifyDatabricksError(err)
	}
	r.cacheColumns = t.Columns
	return r.cacheColumns, nil
}

func (r *mqlDatabricksTable) columns() ([]any, error) {
	infos, err := r.columnInfos()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(infos))
	for i := range infos {
		res, err := CreateResource(r.MqlRuntime, "databricks.table.column", columnFields(r.FullName.Data, infos[i]))
		if err != nil {
			return nil, err
		}
		col := res.(*mqlDatabricksTableColumn)
		col.cacheMaskFunction = columnMaskFunction(infos[i])
		out = append(out, col)
	}
	return out, nil
}

// splitFunctionName splits catalog.schema.function. Unity Catalog identifiers
// in a mask's function name are not quoted, so a name that does not split into
// three parts cannot be resolved.
func splitFunctionName(fullName string) (catalogName, schemaName, name string, ok bool) {
	parts := strings.SplitN(fullName, ".", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// findFunction returns the function in fns whose fullName matches, compared
// without case since Unity Catalog folds identifiers to lower case.
func findFunction(fns []any, fullName string) *mqlDatabricksFunction {
	for _, f := range fns {
		fn, ok := f.(*mqlDatabricksFunction)
		if ok && strings.EqualFold(fn.FullName.Data, fullName) {
			return fn
		}
	}
	return nil
}

// mask resolves the column mask's function against the functions its schema
// lists, one list per schema for the scan.
func (r *mqlDatabricksTableColumn) mask() (*mqlDatabricksFunction, error) {
	if r.cacheMaskFunction == "" {
		r.Mask.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	catalogName, schemaName, _, ok := splitFunctionName(r.cacheMaskFunction)
	if !ok {
		r.Mask.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	schema, err := databricksSchemaByName(r.MqlRuntime, catalogName, schemaName)
	if err != nil {
		return nil, err
	}
	fns := schema.GetFunctions()
	if fns.Error != nil {
		return nil, fns.Error
	}
	if fns.State&plugin.StateIsNull != 0 {
		// The schema's functions could not be read, so the mask cannot be
		// resolved. That is not the same as "no mask".
		return nil, fmt.Errorf("cannot read the functions of schema %s.%s to resolve column mask %s",
			catalogName, schemaName, r.cacheMaskFunction)
	}
	fn := findFunction(fns.Data, r.cacheMaskFunction)
	if fn == nil {
		r.Mask.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return fn, nil
}
