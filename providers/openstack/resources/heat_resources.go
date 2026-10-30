// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"

	"github.com/gophercloud/gophercloud/v2/openstack/orchestration/v1/stackresources"
	"github.com/gophercloud/gophercloud/v2/openstack/orchestration/v1/stacktemplates"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlOpenstackOrchestrationStackResourceInternal struct {
	cacheStack *mqlOpenstackOrchestrationStack
}

// resources reads the objects this stack created and still manages. Heat only
// exposes them under their stack, so this is one call per stack and it stays
// lazy until the field is asked for.
func (r *mqlOpenstackOrchestrationStack) resources() ([]any, error) {
	client, err := conn(r.MqlRuntime).OrchestrationClient()
	if err != nil {
		return nil, err
	}
	pages, err := stackresources.List(client, r.Name.Data, r.Id.Data, stackresources.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := stackresources.ExtractResources(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, item := range items {
		res, err := CreateResource(r.MqlRuntime, "openstack.orchestration.stack.resource", map[string]*llx.RawData{
			"__id":         llx.StringData("openstack.orchestration.stack.resource/" + r.Id.Data + "/" + item.Name),
			"name":         llx.StringData(item.Name),
			"logicalId":    llx.StringData(item.LogicalID),
			"physicalId":   llx.StringData(item.PhysicalID),
			"type":         llx.StringData(item.Type),
			"status":       llx.StringData(item.Status),
			"statusReason": llx.StringData(item.StatusReason),
			"description":  llx.StringData(item.Description),
			"requiredBy":   stringSliceData(requiredByNames(item.RequiredBy)),
			"createdAt":    llx.TimeDataPtr(timePtr(item.CreationTime)),
			"updatedAt":    llx.TimeDataPtr(timePtr(item.UpdatedTime)),
		})
		if err != nil {
			return nil, err
		}
		mqlRes := res.(*mqlOpenstackOrchestrationStackResource)
		mqlRes.cacheStack = r
		out = append(out, mqlRes)
	}
	return out, nil
}

// requiredByNames renders the dependency list, whose entries the API types only
// as free-form values, to the resource names it holds.
func requiredByNames(in []any) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		if s, ok := raw.(string); ok {
			out = append(out, s)
			continue
		}
		out = append(out, fmt.Sprint(raw))
	}
	return out
}

func (r *mqlOpenstackOrchestrationStackResource) stack() (*mqlOpenstackOrchestrationStack, error) {
	if r.cacheStack == nil {
		r.Stack.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return r.cacheStack, nil
}

// template reads the stack's template body. It is a separate call and can be
// large, so it stays lazy until the field is asked for.
func (r *mqlOpenstackOrchestrationStack) template() (any, error) {
	client, err := conn(r.MqlRuntime).OrchestrationClient()
	if err != nil {
		return nil, err
	}
	body, err := stacktemplates.Get(ctx(), client, r.Name.Data, r.Id.Data).Extract()
	if err != nil {
		if translateOpenstackError(err) == nil {
			r.Template.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	// Extract hands back the template as JSON, so decoding it yields the
	// JSON-native values a dict is built from.
	var out any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}
