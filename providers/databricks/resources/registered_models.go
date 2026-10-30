// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strconv"

	"github.com/databricks/databricks-sdk-go/apierr"
	"github.com/databricks/databricks-sdk-go/service/catalog"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

func (r *mqlDatabricks) registeredModels() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	models, err := ws.RegisteredModels.ListAll(context.Background(), catalog.ListRegisteredModelsRequest{})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range models {
		res, err := newMqlDatabricksRegisteredModel(r.MqlRuntime, models[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlDatabricksRegisteredModel(runtime *plugin.Runtime, m catalog.RegisteredModelInfo) (*mqlDatabricksRegisteredModel, error) {
	aliases, err := convert.JsonToDictSlice(m.Aliases)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "databricks.registeredModel", map[string]*llx.RawData{
		"__id":            llx.StringData("databricks.registeredModel/" + m.FullName),
		"fullName":        llx.StringData(m.FullName),
		"name":            llx.StringData(m.Name),
		"catalogName":     llx.StringData(m.CatalogName),
		"schemaName":      llx.StringData(m.SchemaName),
		"owner":           llx.StringData(m.Owner),
		"comment":         llx.StringData(m.Comment),
		"storageLocation": llx.StringData(m.StorageLocation),
		"browseOnly":      llx.BoolData(m.BrowseOnly),
		"createdAt":       llx.TimeDataPtr(epochMsTime(m.CreatedAt)),
		"createdBy":       llx.StringData(m.CreatedBy),
		"updatedAt":       llx.TimeDataPtr(epochMsTime(m.UpdatedAt)),
		"updatedBy":       llx.StringData(m.UpdatedBy),
		"aliases":         llx.ArrayData(aliases, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksRegisteredModel), nil
}

// catalog resolves the parent catalog this model belongs to, hydrated by name
// through the catalog's init.
func (r *mqlDatabricksRegisteredModel) catalog() (*mqlDatabricksCatalog, error) {
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

// schema resolves the parent schema this model belongs to, hydrated by its
// catalog and schema names through the schema's init.
func (r *mqlDatabricksRegisteredModel) schema() (*mqlDatabricksSchema, error) {
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

// grants fetches the privilege assignments on the model. Unity Catalog governs
// registered models under the REGISTERED_MODEL securable type. databricks-sdk-go
// v0.160.0 has no catalog.SecurableTypeRegisteredModel constant (its enum stops
// at the older securables), so the securable string is passed directly. A
// metastore where the registered-model securable is not enabled returns 400, and
// a caller without permission gets 403/404; those degrade to an empty list so the
// model never fails a query, while unexpected errors propagate.
func (r *mqlDatabricksRegisteredModel) grants() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	grants, err := mqlDatabricksGrants(r.MqlRuntime, ws, catalog.SecurableType("REGISTERED_MODEL"), r.FullName.Data)
	if err != nil {
		if isDatabricksGrantsUnavailable(err) {
			return []any{}, nil
		}
		return nil, err
	}
	return grants, nil
}

// isDatabricksGrantsUnavailable reports whether a grants lookup failed because
// the securable is not enabled on the metastore (400) or the caller cannot read
// it (403/404), rather than a transient failure that should propagate.
func isDatabricksGrantsUnavailable(err error) bool {
	if apiErr, ok := errors.AsType[*apierr.APIError](err); ok {
		switch apiErr.StatusCode {
		case 400, 403, 404:
			return true
		}
	}
	return false
}

func (r *mqlDatabricksRegisteredModel) modelVersions() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	// ListAll follows the response page tokens. A registered model's version
	// count is bounded in practice (UC retains a limited version history), so
	// listing every version in one pass is acceptable here.
	versions, err := ws.ModelVersions.ListAll(context.Background(), catalog.ListModelVersionsRequest{
		FullName: r.FullName.Data,
	})
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range versions {
		v := versions[i]
		aliases, err := convert.JsonToDictSlice(v.Aliases)
		if err != nil {
			return nil, err
		}

		res, err := CreateResource(r.MqlRuntime, "databricks.modelVersion", map[string]*llx.RawData{
			"__id":            llx.StringData("databricks.modelVersion/" + v.ModelName + "/" + strconv.Itoa(v.Version)),
			"modelName":       llx.StringData(v.ModelName),
			"version":         llx.IntData(v.Version),
			"status":          llx.StringData(string(v.Status)),
			"source":          llx.StringData(v.Source),
			"runId":           llx.StringData(v.RunId),
			"storageLocation": llx.StringData(v.StorageLocation),
			"comment":         llx.StringData(v.Comment),
			"createdAt":       llx.TimeDataPtr(epochMsTime(v.CreatedAt)),
			"createdBy":       llx.StringData(v.CreatedBy),
			"updatedAt":       llx.TimeDataPtr(epochMsTime(v.UpdatedAt)),
			"aliases":         llx.ArrayData(aliases, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
