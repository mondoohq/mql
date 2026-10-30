// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/openai/openai-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// mapModel builds the resource args for an openai.model. Both the collection
// path and the single-object init share it so the two paths cannot diverge.
func mapModel(m openai.Model) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":      llx.StringData(m.ID),
		"id":        llx.StringData(m.ID),
		"createdAt": llx.TimeDataPtr(unixToNullableTime(m.Created)),
		"ownedBy":   llx.StringData(m.OwnedBy),
	}
}

func (r *mqlOpenai) models() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := dataPlaneClient(conn, "openai.models")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Models.ListAutoPaging(ctx)
	var res []any
	for iter.Next() {
		m := iter.Current()
		mqlModel, err := CreateResource(r.MqlRuntime, "openai.model", mapModel(m))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlModel)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list models: %w", err)
	}
	return res, nil
}

func initOpenaiModel(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok || idRaw == nil || idRaw.Value == nil {
		return args, nil, nil
	}
	modelID, ok := idRaw.Value.(string)
	if !ok || modelID == "" {
		return args, nil, nil
	}

	conn := openaiConn(runtime)
	client, err := dataPlaneClient(conn, "openai.model")
	if err != nil {
		return nil, nil, err
	}
	if client == nil {
		return nil, nil, fmt.Errorf("cannot fetch model %s: no project API key configured", modelID)
	}
	m, err := client.Models.Get(context.Background(), modelID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get model %s: %w", modelID, err)
	}
	return mapModel(*m), nil, nil
}

func (r *mqlOpenaiModel) isFineTuned() (bool, error) {
	return strings.HasPrefix(r.Id.Data, "ft:"), nil
}

func (r *mqlOpenaiModel) baseModel() (string, error) {
	if !strings.HasPrefix(r.Id.Data, "ft:") {
		return "", nil
	}
	// Fine-tuned model ID format: ft:<base-model>:<org>:<suffix>:<id>
	parts := strings.SplitN(r.Id.Data, ":", 3)
	if len(parts) >= 2 {
		return parts[1], nil
	}
	return "", nil
}

// openaiModelList returns the account model collection through the openai
// resource so the underlying list call is made once per scan.
func openaiModelList(runtime *plugin.Runtime) ([]any, error) {
	obj, err := CreateResource(runtime, "openai", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	models := obj.(*mqlOpenai).GetModels()
	if models.Error != nil {
		return nil, models.Error
	}
	return models.Data, nil
}

// resolveModel finds the model with the given id in the account model list.
// Resolving through the cached list keeps a reference from costing a get per
// referring object. A model named by a stored object can be retired from the
// catalog, so a miss is reported as (nil, nil) for the caller to null rather
// than as an error.
func resolveModel(runtime *plugin.Runtime, modelID string) (*mqlOpenaiModel, error) {
	models, err := openaiModelList(runtime)
	if err != nil {
		return nil, err
	}
	for i := range models {
		m, ok := models[i].(*mqlOpenaiModel)
		if !ok {
			continue
		}
		if m.Id.Data == modelID {
			return m, nil
		}
	}
	return nil, nil
}
