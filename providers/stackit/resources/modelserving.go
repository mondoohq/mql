// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	modelserving "github.com/stackitcloud/stackit-sdk-go/services/modelserving/v1api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// ------------------------- Model Serving tokens -------------------------

func modelServingTokenArgs(t *modelserving.Token) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":          llx.StringData(t.GetId()),
		"name":        llx.StringData(t.GetName()),
		"description": llx.StringData(t.GetDescription()),
		"state":       llx.StringData(string(t.GetState())),
		"region":      llx.StringData(t.GetRegion()),
		"validUntil":  llx.TimeDataPtr(timeOrNil(t.GetValidUntilOk())),
	}
}

func (r *mqlStackitModelServing) tokens() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ModelServing()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListTokens(bgctx(), c.Region(), c.ProjectID()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	tokens, _ := resp.GetTokensOk()
	out := make([]any, 0, len(tokens))
	for i := range tokens {
		res, err := CreateResource(r.MqlRuntime, "stackit.modelServing.token", modelServingTokenArgs(&tokens[i]))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitModelServingToken) id() (string, error) {
	return "stackit.modelServing.token/" + r.Id.Data, nil
}

func initStackitModelServingToken(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		return args, nil, nil
	}
	c := conn(runtime)
	client, err := c.ModelServing()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DefaultAPI.GetToken(bgctx(), c.Region(), c.ProjectID(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	token, ok := resp.GetTokenOk()
	if !ok {
		return nil, nil, fmt.Errorf("stackit model serving token %q not found", id)
	}
	res, err := CreateResource(runtime, "stackit.modelServing.token", modelServingTokenArgs(token))
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

// ------------------------- Model Serving models -------------------------

func (r *mqlStackitModelServing) models() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.ModelServing()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListModels(bgctx(), c.Region()).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	models, _ := resp.GetModelsOk()
	out := make([]any, 0, len(models))
	for i := range models {
		m := models[i]
		skus := m.GetSkus()
		skuList := make([]any, 0, len(skus))
		for j := range skus {
			skuList = append(skuList, toDict(skus[j]))
		}
		res, err := CreateResource(r.MqlRuntime, "stackit.modelServing.model", map[string]*llx.RawData{
			"id":            llx.StringData(m.GetId()),
			"name":          llx.StringData(m.GetName()),
			"displayedName": llx.StringData(m.GetDisplayedName()),
			"description":   llx.StringData(m.GetDescription()),
			"type":          llx.StringData(string(m.GetType())),
			"category":      llx.StringData(string(m.GetCategory())),
			"region":        llx.StringData(m.GetRegion()),
			"url":           llx.StringData(m.GetUrl()),
			"tags":          strSliceData(m.GetTags()),
			"skus":          llx.ArrayData(skuList, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlStackitModelServingModel) id() (string, error) {
	return "stackit.modelServing.model/" + r.Id.Data, nil
}
