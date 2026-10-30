// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	databricks "github.com/databricks/databricks-sdk-go"
	"github.com/databricks/databricks-sdk-go/service/catalog"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// functionCacheKey builds the cache key for a Unity Catalog function. A
// function name is three-level (catalog.schema.function) and the same name may
// legitimately exist in two schemas, so the fully qualified name is the
// starting point. Unity Catalog also allows overloads, which share a fully
// qualified name and differ only by signature, so the function id is appended
// when the API reports one. Two functions collapsing onto one key would make
// CreateResource hand back the first one for both, under-reporting the set of
// bodies that run with their owner's privileges.
func functionCacheKey(f catalog.FunctionInfo) string {
	name := f.FullName
	if name == "" {
		name = f.CatalogName + "." + f.SchemaName + "." + f.Name
	}
	if f.FunctionId != "" {
		return "databricks.function/" + name + "/" + f.FunctionId
	}
	return "databricks.function/" + name
}

// functionFields maps one function record to its MQL fields. Kept apart from
// the API call so the mapping can be asserted directly, in particular that
// securityType survives as reported: a function that runs DEFINER but reads as
// anything else silently drops a standing privilege boundary from the audit.
//
// The routine definition (the function body) is deliberately not mapped. It is
// author-controlled text that regularly carries credentials inline, and
// nothing in the security question this resource answers needs it.
func functionFields(f catalog.FunctionInfo) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":             llx.StringData(functionCacheKey(f)),
		"id":               llx.StringData(f.FunctionId),
		"name":             llx.StringData(f.Name),
		"fullName":         llx.StringData(f.FullName),
		"catalogName":      llx.StringData(f.CatalogName),
		"schemaName":       llx.StringData(f.SchemaName),
		"owner":            llx.StringData(f.Owner),
		"comment":          llx.StringData(f.Comment),
		"securityType":     llx.StringData(string(f.SecurityType)),
		"routineBody":      llx.StringData(string(f.RoutineBody)),
		"externalLanguage": llx.StringData(f.ExternalLanguage),
		"externalName":     llx.StringData(f.ExternalName),
		"sqlDataAccess":    llx.StringData(string(f.SqlDataAccess)),
		"sqlPath":          llx.StringData(f.SqlPath),
		"isDeterministic":  llx.BoolData(f.IsDeterministic),
		"isNullCall":       llx.BoolData(f.IsNullCall),
		"dataType":         llx.StringData(string(f.DataType)),
		"fullDataType":     llx.StringData(f.FullDataType),
		"parameterStyle":   llx.StringData(string(f.ParameterStyle)),
		"metastoreId":      llx.StringData(f.MetastoreId),
		"browseOnly":       llx.BoolData(f.BrowseOnly),
		"createdAt":        llx.TimeDataPtr(epochMsTime(f.CreatedAt)),
		"createdBy":        llx.StringData(f.CreatedBy),
		"updatedAt":        llx.TimeDataPtr(epochMsTime(f.UpdatedAt)),
		"updatedBy":        llx.StringData(f.UpdatedBy),
	}
}

// functions lists the Unity Catalog functions registered in the schema.
//
// A workspace without Unity Catalog reaches this through no catalog at all, so
// it never runs; a schema that holds no functions is an empty list. A caller
// that may not read the schema's functions gets null instead, because an empty
// list would read as "this schema defines no DEFINER functions" on a schema
// nobody looked inside.
func (r *mqlDatabricksSchema) functions() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	fns, err := listFunctions(context.Background(), ws, r.CatalogName.Data, r.Name.Data)
	if err != nil {
		if isDatabricksUnreadable(err) {
			r.Functions = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		if isDatabricksFeatureUnavailable(err) {
			return []any{}, nil
		}
		return nil, err
	}

	out := []any{}
	for i := range fns {
		res, err := CreateResource(r.MqlRuntime, "databricks.function", functionFields(fns[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// functionPageLimit bounds how many functions one schema may yield. It is far
// above any real schema and exists only as a termination guard: the SDK's
// paginating iterator stops when a response omits next_page_token and has no
// check for a cursor that never advances, so an endpoint returning the same
// token forever would otherwise walk without end. Exceeding the bound is
// reported as an error rather than silently truncating the list, because a
// short list satisfies every assertion written about it.
const functionPageLimit = 100000

// listFunctions walks every page of a schema's Unity Catalog functions.
// MaxResults 0 selects the paginated form the API recommends. A page may come
// back empty while still carrying a next page token, so an empty page is not
// an end-of-list signal and the walk keeps going until the token is absent.
func listFunctions(ctx context.Context, ws *databricks.WorkspaceClient, catalogName, schemaName string) ([]catalog.FunctionInfo, error) {
	it := ws.Functions.List(ctx, catalog.ListFunctionsRequest{
		CatalogName: catalogName,
		SchemaName:  schemaName,
		MaxResults:  0,
	})

	out := []catalog.FunctionInfo{}
	for it.HasNext(ctx) {
		fn, err := it.Next(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, fn)
		if len(out) > functionPageLimit {
			return nil, fmt.Errorf(
				"databricks returned more than %d functions for schema %s.%s, which means its pagination cursor is not advancing",
				functionPageLimit, catalogName, schemaName)
		}
	}
	return out, nil
}

// catalog resolves the parent catalog this function belongs to, hydrated by
// name through the catalog's init.
func (r *mqlDatabricksFunction) catalog() (*mqlDatabricksCatalog, error) {
	if r.CatalogName.Data == "" {
		r.Catalog.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	c, err := NewResource(r.MqlRuntime, "databricks.catalog", map[string]*llx.RawData{
		"name": llx.StringData(r.CatalogName.Data),
	})
	if err != nil {
		return nil, err
	}
	return c.(*mqlDatabricksCatalog), nil
}

// schema resolves the parent schema this function belongs to, hydrated by its
// catalog and schema names through the schema's init.
func (r *mqlDatabricksFunction) schema() (*mqlDatabricksSchema, error) {
	if r.CatalogName.Data == "" || r.SchemaName.Data == "" {
		r.Schema.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	s, err := NewResource(r.MqlRuntime, "databricks.schema", map[string]*llx.RawData{
		"catalogName": llx.StringData(r.CatalogName.Data),
		"name":        llx.StringData(r.SchemaName.Data),
	})
	if err != nil {
		return nil, err
	}
	return s.(*mqlDatabricksSchema), nil
}

// grants fetches the privilege assignments on the function. EXECUTE on a
// DEFINER function is what lets a caller run the body with the owner's
// privileges, so the grants and the owner together describe who crosses that
// boundary.
func (r *mqlDatabricksFunction) grants() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	grants, err := mqlDatabricksGrants(r.MqlRuntime, ws, catalog.SecurableTypeFunction, r.FullName.Data)
	if err != nil {
		if isDatabricksUnreadable(err) {
			r.Grants = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		if isDatabricksFeatureUnavailable(err) {
			return []any{}, nil
		}
		return nil, err
	}
	return grants, nil
}
