// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

// searchIndexes lists the Atlas Search and Atlas Vector Search indexes defined
// on the cluster. A single cluster-wide call returns every index across all
// databases and collections, discriminated by the type field ("search" versus
// "vectorSearch").
func (c *mqlMongodbatlasCluster) searchIndexes() ([]any, error) {
	pid, err := projectID(c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	name := c.Name.Data

	indexes, httpResp, err := atlasClient(c.MqlRuntime).AtlasSearchAPI.
		ListClusterSearchIndexes(context.Background(), pid, name).Execute()
	if err != nil {
		// A credential that may not read the endpoint has not established
		// anything about the cluster's indexes, so the field renders null. An
		// empty list would assert the cluster has none, which is the claim a
		// search-index audit reads and would wrongly pass on.
		if isAccessDenied(httpResp) {
			c.SearchIndexes.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		// Atlas Search is not offered on every cluster tier or state. That
		// genuinely answers the question with "no indexes", so it stays empty.
		if httpResp != nil && httpResp.StatusCode == http.StatusNotFound {
			return []any{}, nil
		}
		return nil, err
	}

	out := make([]any, 0, len(indexes))
	for i := range indexes {
		res, err := newMqlMongodbatlasSearchIndex(c.MqlRuntime, name, indexes[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlMongodbatlasSearchIndex(runtime *plugin.Runtime, clusterName string, idx admin.SearchIndexResponse) (*mqlMongodbatlasSearchIndex, error) {
	args := map[string]*llx.RawData{
		"__id":           llx.StringData("mongodbatlas.searchIndex/" + clusterName + "/" + idx.GetIndexID()),
		"id":             llx.StringData(idx.GetIndexID()),
		"name":           llx.StringData(idx.GetName()),
		"type":           llx.StringData(idx.GetType()),
		"database":       llx.StringData(idx.GetDatabase()),
		"collectionName": llx.StringData(idx.GetCollectionName()),
		"status":         llx.StringData(idx.GetStatus()),
		"queryable":      llx.BoolData(idx.GetQueryable()),
	}

	if def, ok := idx.GetLatestDefinitionOk(); ok {
		dict, err := convert.JsonToDict(def)
		if err != nil {
			return nil, err
		}
		args["latestDefinition"] = llx.DictData(dict)
	} else {
		args["latestDefinition"] = llx.NilData
	}

	if ver, ok := idx.GetLatestDefinitionVersionOk(); ok {
		dict, err := convert.JsonToDict(ver)
		if err != nil {
			return nil, err
		}
		args["latestDefinitionVersion"] = llx.DictData(dict)
	} else {
		args["latestDefinitionVersion"] = llx.NilData
	}

	if detail, ok := idx.GetStatusDetailOk(); ok {
		list, err := convert.JsonToDictSlice(detail)
		if err != nil {
			return nil, err
		}
		args["statusDetail"] = llx.ArrayData(list, types.Dict)
	} else {
		args["statusDetail"] = llx.ArrayData([]any{}, types.Dict)
	}

	res, err := CreateResource(runtime, "mongodbatlas.searchIndex", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlMongodbatlasSearchIndex), nil
}
