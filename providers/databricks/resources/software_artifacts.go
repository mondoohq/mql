// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/databricks/databricks-sdk-go/listing"
	"github.com/databricks/databricks-sdk-go/service/softwareartifacts"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

const (
	softwareArtifactNamePrefix = "software-artifacts/"
	softwareArtifactVersionSep = "/versions/"
)

// softwareArtifactFullName strips the resource-name prefix from an artifact
// name, leaving catalog.schema.artifact. A name without the documented prefix
// reports null rather than a guess at which part is which.
func softwareArtifactFullName(name string) *llx.RawData {
	full, ok := strings.CutPrefix(name, softwareArtifactNamePrefix)
	if !ok || full == "" || strings.Contains(full, "/") {
		return llx.NilData
	}
	return llx.StringData(full)
}

// softwareArtifactVersionName returns the version segment of a version's
// resource name, or null when the name does not carry one.
func softwareArtifactVersionName(name string) *llx.RawData {
	i := strings.LastIndex(name, softwareArtifactVersionSep)
	if i < 0 {
		return llx.NilData
	}
	v := name[i+len(softwareArtifactVersionSep):]
	if v == "" {
		return llx.NilData
	}
	return llx.StringData(v)
}

// softwareArtifactFields maps one artifact record to its MQL fields. The
// resource name is unique within the metastore, so it is the cache key.
func softwareArtifactFields(a softwareartifacts.SoftwareArtifact) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":       llx.StringData("databricks.softwareArtifact/" + a.Name),
		"name":       llx.StringData(a.Name),
		"fullName":   softwareArtifactFullName(a.Name),
		"owner":      llx.StringData(a.Owner),
		"createdBy":  llx.StringData(a.CreatedBy),
		"createTime": llx.TimeDataPtr(sdkTime(a.CreateTime)),
		"updatedBy":  llx.StringData(a.UpdatedBy),
		"updateTime": llx.TimeDataPtr(sdkTime(a.UpdateTime)),
	}
}

// softwareArtifactVersionFields maps one version record to its MQL fields.
// The version's resource name carries the artifact's full name and the
// version, so it is unique across artifacts and schemas.
func softwareArtifactVersionFields(v softwareartifacts.SoftwareArtifactVersion) map[string]*llx.RawData {
	accel := llx.NilData
	if v.ImageAccelerationDetails != nil && v.ImageAccelerationDetails.Status != "" {
		accel = llx.StringData(string(v.ImageAccelerationDetails.Status))
	}
	tags := make([]any, 0, len(v.Tags))
	for _, t := range v.Tags {
		tags = append(tags, t)
	}
	return map[string]*llx.RawData{
		"__id":                    llx.StringData("databricks.softwareArtifact.version/" + v.Name),
		"name":                    llx.StringData(v.Name),
		"version":                 softwareArtifactVersionName(v.Name),
		"digest":                  llx.StringData(v.Digest),
		"tags":                    llx.ArrayData(tags, types.String),
		"imageAccelerationStatus": accel,
		"createdBy":               llx.StringData(v.CreatedBy),
		"createTime":              llx.TimeDataPtr(sdkTime(v.CreateTime)),
		"updatedBy":               llx.StringData(v.UpdatedBy),
		"updateTime":              llx.TimeDataPtr(sdkTime(v.UpdateTime)),
	}
}

// softwareArtifactPageLimit bounds how many records one listing may yield. It
// is far above any real schema and exists only as a termination guard behind
// the repeated-name check in collectUniqueByName.
const softwareArtifactPageLimit = 100000

// collectUniqueByName drains a paginating iterator. The SDK's iterator stops
// only when a response omits next_page_token and has no check for a cursor
// that never advances. Resource names are unique within a listing, so a name
// seen twice means the server handed back a page it already sent; that is
// reported as an error after one repeated page rather than walking forever or
// returning a list with duplicates. Exceeding the bound is also an error
// rather than a silent truncation, because a short list satisfies every
// assertion written about it.
func collectUniqueByName[T any](ctx context.Context, it listing.Iterator[T], name func(T) string, what string) ([]T, error) {
	out := []T{}
	seen := map[string]struct{}{}
	for it.HasNext(ctx) {
		item, err := it.Next(ctx)
		if err != nil {
			return nil, err
		}
		if n := name(item); n != "" {
			if _, dup := seen[n]; dup {
				return nil, fmt.Errorf("databricks returned %s %q twice, which means its pagination cursor is not advancing", what, n)
			}
			seen[n] = struct{}{}
		}
		out = append(out, item)
		if len(out) > softwareArtifactPageLimit {
			return nil, fmt.Errorf("databricks returned more than %d %ss, which means its pagination cursor is not advancing", softwareArtifactPageLimit, what)
		}
	}
	return out, nil
}

// softwareArtifactSchemaParent builds the parent resource name the listing
// expects for a schema, schemas/{catalog}.{schema}.
func softwareArtifactSchemaParent(catalogName, schemaName, fullName string) string {
	if fullName == "" {
		fullName = catalogName + "." + schemaName
	}
	return "schemas/" + fullName
}

// softwareArtifacts lists the container images registered in the schema.
func (r *mqlDatabricksSchema) softwareArtifacts() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	it := ws.SoftwareArtifacts.ListSoftwareArtifacts(ctx, softwareartifacts.ListSoftwareArtifactsRequest{
		Parent: softwareArtifactSchemaParent(r.CatalogName.Data, r.Name.Data, r.FullName.Data),
	})
	list, err := collectUniqueByName(ctx, it, func(a softwareartifacts.SoftwareArtifact) string { return a.Name }, "software artifact")
	if err != nil {
		if !plugin.StructuredErrors() {
			if isDatabricksUnreadable(err) {
				r.SoftwareArtifacts = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
				return nil, nil
			}
			if isDatabricksFeatureUnavailable(err) {
				return []any{}, nil
			}
		}
		return nil, classifyDatabricksError(err)
	}

	out := []any{}
	for i := range list {
		res, err := CreateResource(r.MqlRuntime, "databricks.softwareArtifact", softwareArtifactFields(list[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// versions lists the artifact's versions.
func (r *mqlDatabricksSoftwareArtifact) versions() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	it := ws.SoftwareArtifacts.ListSoftwareArtifactVersions(ctx, softwareartifacts.ListSoftwareArtifactVersionsRequest{
		Parent: r.Name.Data,
	})
	list, err := collectUniqueByName(ctx, it, func(v softwareartifacts.SoftwareArtifactVersion) string { return v.Name }, "software artifact version")
	if err != nil {
		if !plugin.StructuredErrors() {
			if isDatabricksUnreadable(err) {
				r.Versions = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
				return nil, nil
			}
			if isDatabricksFeatureUnavailable(err) {
				return []any{}, nil
			}
		}
		return nil, classifyDatabricksError(err)
	}

	out := []any{}
	for i := range list {
		res, err := CreateResource(r.MqlRuntime, "databricks.softwareArtifact.version", softwareArtifactVersionFields(list[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
