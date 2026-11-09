// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/databricks/databricks-sdk-go/service/compute"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// serverlessComputeFields maps one serverless compute record to its MQL
// fields. Kept apart from the API call so the absent creation time can be
// asserted to arrive as null rather than as the zero time.
func serverlessComputeFields(c compute.ServerlessCompute) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":       llx.StringData("databricks.serverlessCompute/" + c.ServerlessComputeId),
		"id":         llx.StringData(c.ServerlessComputeId),
		"name":       llx.StringData(c.Name),
		"isDefault":  llx.BoolData(c.IsDefault),
		"canManage":  llx.BoolData(c.CanManage),
		"canUse":     llx.BoolData(c.CanUse),
		"createTime": llx.TimeDataPtr(sdkTime(c.CreateTime)),
	}
}

// serverlessComputes lists the interactive serverless computes the calling
// identity may use or manage.
func (r *mqlDatabricks) serverlessComputes() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	list, err := ws.ServerlessComputeService.ListAll(context.Background(), compute.ListServerlessComputesRequest{})
	if err != nil {
		if !plugin.StructuredErrors() {
			if isDatabricksUnreadable(err) {
				r.ServerlessComputes = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
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
		res, err := CreateResource(r.MqlRuntime, "databricks.serverlessCompute", serverlessComputeFields(list[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
