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
	"go.mondoo.com/mql/types"
)

func (r *mqlDatabricks) catalogs() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	catalogs, err := ws.Catalogs.ListAll(context.Background(), catalog.ListCatalogsRequest{})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range catalogs {
		res, err := newMqlDatabricksCatalog(r.MqlRuntime, catalogs[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// newMqlDatabricksCatalog maps a Unity Catalog catalog to its resource. Shared
// by the list path and the init lookup so a catalog hydrated by name carries
// the same fields as a listed one.
func newMqlDatabricksCatalog(runtime *plugin.Runtime, c catalog.CatalogInfo) (*mqlDatabricksCatalog, error) {
	res, err := CreateResource(runtime, "databricks.catalog", map[string]*llx.RawData{
		"__id":          llx.StringData("databricks.catalog/" + c.FullName),
		"name":          llx.StringData(c.Name),
		"fullName":      llx.StringData(c.FullName),
		"owner":         llx.StringData(c.Owner),
		"metastoreId":   llx.StringData(c.MetastoreId),
		"isolationMode": llx.StringData(string(c.IsolationMode)),
		"comment":       llx.StringData(c.Comment),
		"catalogType":   llx.StringData(string(c.CatalogType)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksCatalog), nil
}

// initDatabricksCatalog resolves a single catalog by name so typed references
// (such as databricks.schema.catalog) can hydrate a full catalog from its name.
func initDatabricksCatalog(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	nameRaw, ok := args["name"]
	if !ok {
		return args, nil, nil
	}
	name, _ := nameRaw.Value.(string)
	if name == "" {
		return nil, nil, fmt.Errorf("databricks.catalog requires a non-empty name")
	}

	ws, err := workspaceClient(runtime)
	if err != nil {
		return nil, nil, err
	}
	c, err := ws.Catalogs.GetByName(context.Background(), name)
	if err != nil {
		return nil, nil, err
	}
	res, err := newMqlDatabricksCatalog(runtime, *c)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlDatabricksCatalog) schemas() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	schemas, err := ws.Schemas.ListAll(context.Background(), catalog.ListSchemasRequest{CatalogName: r.Name.Data})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range schemas {
		res, err := newMqlDatabricksSchema(r.MqlRuntime, schemas[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// newMqlDatabricksSchema maps a Unity Catalog schema to its resource. Shared by
// the list path and the init lookup so a schema hydrated by full name carries
// the same fields as a listed one.
func newMqlDatabricksSchema(runtime *plugin.Runtime, s catalog.SchemaInfo) (*mqlDatabricksSchema, error) {
	res, err := CreateResource(runtime, "databricks.schema", map[string]*llx.RawData{
		"__id":        llx.StringData("databricks.schema/" + s.FullName),
		"id":          llx.StringData(s.SchemaId),
		"name":        llx.StringData(s.Name),
		"fullName":    llx.StringData(s.FullName),
		"catalogName": llx.StringData(s.CatalogName),
		"owner":       llx.StringData(s.Owner),
		"comment":     llx.StringData(s.Comment),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksSchema), nil
}

// initDatabricksSchema resolves a single schema by its catalog and schema name
// so typed references (such as databricks.volume.schema) can hydrate a full
// schema from the catalog and schema names the caller already carries.
func initDatabricksSchema(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	catalogNameRaw, ok := args["catalogName"]
	if !ok {
		return args, nil, nil
	}
	nameRaw, ok := args["name"]
	if !ok {
		return args, nil, nil
	}
	catalogName, _ := catalogNameRaw.Value.(string)
	name, _ := nameRaw.Value.(string)
	if catalogName == "" || name == "" {
		return nil, nil, fmt.Errorf("databricks.schema requires a non-empty catalogName and name")
	}

	ws, err := workspaceClient(runtime)
	if err != nil {
		return nil, nil, err
	}
	s, err := ws.Schemas.GetByFullName(context.Background(), catalogName+"."+name)
	if err != nil {
		return nil, nil, err
	}
	res, err := newMqlDatabricksSchema(runtime, *s)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// catalog resolves the parent catalog this schema belongs to, hydrated by name
// through the catalog's init.
func (r *mqlDatabricksSchema) catalog() (*mqlDatabricksCatalog, error) {
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

// catalog resolves the parent catalog this volume belongs to, hydrated by name
// through the catalog's init.
func (r *mqlDatabricksVolume) catalog() (*mqlDatabricksCatalog, error) {
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

// schema resolves the parent schema this volume belongs to, hydrated by its
// catalog and schema names through the schema's init.
func (r *mqlDatabricksVolume) schema() (*mqlDatabricksSchema, error) {
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

func (r *mqlDatabricksCatalog) grants() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return mqlDatabricksGrants(r.MqlRuntime, ws, catalog.SecurableTypeCatalog, r.FullName.Data)
}

func (r *mqlDatabricksSchema) grants() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return mqlDatabricksGrants(r.MqlRuntime, ws, catalog.SecurableTypeSchema, r.FullName.Data)
}

// mqlDatabricksGrants fetches the direct privilege assignments on a Unity
// Catalog securable and maps each principal's grant to a databricks.grant.
func mqlDatabricksGrants(runtime *plugin.Runtime, ws *databricks.WorkspaceClient, securableType catalog.SecurableType, fullName string) ([]any, error) {
	// ListAll follows the response page tokens; GetBySecurableTypeAndFullName
	// would return only the first page.
	assignments, err := ws.Grants.ListAll(context.Background(), catalog.ListPrivilegeAssignmentsRequest{
		SecurableType: string(securableType),
		FullName:      fullName,
	})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range assignments {
		pa := assignments[i]
		privileges := make([]any, 0, len(pa.Privileges))
		for _, p := range pa.Privileges {
			privileges = append(privileges, string(p))
		}
		res, err := CreateResource(runtime, "databricks.grant", map[string]*llx.RawData{
			"__id":          llx.StringData(string(securableType) + "/" + fullName + "/" + pa.Principal),
			"principal":     llx.StringData(pa.Principal),
			"securableType": llx.StringData(string(securableType)),
			"securableName": llx.StringData(fullName),
			"privileges":    llx.ArrayData(privileges, types.String),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
