// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

func (r *mqlMongodbatlas) resourcePolicies() ([]any, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	policies, httpResp, err := atlasClient(r.MqlRuntime).ResourcePoliciesAPI.ListOrgResourcePolicies(context.Background(), oid).Execute()
	if err != nil {
		// Resource policies are the org-wide guardrails, so an empty list says
		// "nothing constrains this organization". A credential without access
		// has not established that, and returning a nil slice would still
		// render as empty, so the field is marked null explicitly.
		if isAccessDenied(httpResp) {
			r.ResourcePolicies.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		// An org without the feature genuinely has no policies.
		if httpResp != nil && httpResp.StatusCode == http.StatusNotFound {
			return []any{}, nil
		}
		return nil, err
	}

	out := []any{}
	for i := range policies {
		p := policies[i]

		statements := []any{}
		for _, stmt := range p.GetPolicies() {
			statements = append(statements, map[string]any{
				"id":   stmt.GetId(),
				"body": stmt.GetBody(),
			})
		}

		createdBy := p.GetCreatedByUser()
		lastUpdatedBy := p.GetLastUpdatedByUser()

		res, err := CreateResource(r.MqlRuntime, "mongodbatlas.resourcePolicy", map[string]*llx.RawData{
			"__id":              llx.StringData("mongodbatlas.resourcePolicy/" + oid + "/" + p.GetId()),
			"id":                llx.StringData(p.GetId()),
			"name":              llx.StringData(p.GetName()),
			"description":       llx.StringData(p.GetDescription()),
			"createdByUser":     llx.StringData(createdBy.GetName()),
			"createdDate":       llx.TimeDataPtr(timePtr(p.GetCreatedDate())),
			"lastUpdatedByUser": llx.StringData(lastUpdatedBy.GetName()),
			"lastUpdatedDate":   llx.TimeDataPtr(timePtr(p.GetLastUpdatedDate())),
			"policies":          llx.ArrayData(statements, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
