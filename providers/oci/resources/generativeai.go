// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/generativeai"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciAiGenerativeAi) id() (string, error) {
	return "oci.ai.generativeAi", nil
}

// listRegional runs fetch against the Generative AI API in every subscribed
// region and every admitted compartment (see ociListRegionalAI). Base models
// come back from every compartment asked and are deduplicated there.
func (o *mqlOciAiGenerativeAi) listRegional(fetch func(svc *generativeai.GenerativeAiClient, region string, compartmentID string) ([]any, error)) ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	return ociListRegionalAI(o.MqlRuntime, func(region string, compartmentID string) ([]any, error) {
		svc, err := conn.GenerativeAiClient(region)
		if err != nil {
			return nil, err
		}
		return fetch(svc, region, compartmentID)
	})
}

// ----- dedicated AI clusters -----

func (o *mqlOciAiGenerativeAi) dedicatedAiClusters() ([]any, error) {
	return o.listRegional(o.fetchDedicatedAiClusters)
}

func (o *mqlOciAiGenerativeAi) fetchDedicatedAiClusters(svc *generativeai.GenerativeAiClient, _ string, compartmentID string) ([]any, error) {
	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]generativeai.DedicatedAiClusterSummary, *string, error) {
		resp, err := svc.ListDedicatedAiClusters(ctx, generativeai.ListDedicatedAiClustersRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		c := items[i]
		capacity, err := convert.JsonToDict(c.Capacity)
		if err != nil {
			return nil, err
		}
		mqlCluster, err := CreateResource(o.MqlRuntime, "oci.ai.generativeAi.dedicatedAiCluster", map[string]*llx.RawData{
			"id":               llx.StringDataPtr(c.Id),
			"name":             llx.StringDataPtr(c.DisplayName),
			"compartmentID":    llx.StringDataPtr(c.CompartmentId),
			"type":             llx.StringData(string(c.Type)),
			"unitCount":        llx.IntDataPtr(c.UnitCount),
			"unitShape":        llx.StringData(string(c.UnitShape)),
			"capacity":         llx.DictData(capacity),
			"description":      llx.StringDataPtr(c.Description),
			"state":            llx.StringData(string(c.LifecycleState)),
			"lifecycleDetails": llx.StringDataPtr(c.LifecycleDetails),
			"created":          sdkTimeData(c.TimeCreated),
			"timeUpdated":      sdkTimeData(c.TimeUpdated),
			"freeformTags":     llx.MapData(strMapToAny(c.FreeformTags), types.String),
			"definedTags":      llx.MapData(definedTagsToAny(c.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCluster)
	}
	return res, nil
}

func initOciAiGenerativeAiDedicatedAiCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return findOciGenerativeAiByID(runtime, args, "oci.ai.generativeAi.dedicatedAiCluster", (*mqlOciAiGenerativeAi).GetDedicatedAiClusters)
}

func (o *mqlOciAiGenerativeAiDedicatedAiCluster) id() (string, error) {
	return "oci.ai.generativeAi.dedicatedAiCluster/" + o.Id.Data, nil
}

func (o *mqlOciAiGenerativeAiDedicatedAiCluster) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.CompartmentID.Data, &o.Compartment)
}

// ----- models -----

func (o *mqlOciAiGenerativeAi) models() ([]any, error) {
	return o.listRegional(o.fetchModels)
}

func (o *mqlOciAiGenerativeAi) fetchModels(svc *generativeai.GenerativeAiClient, _ string, compartmentID string) ([]any, error) {
	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]generativeai.ModelSummary, *string, error) {
		resp, err := svc.ListModels(ctx, generativeai.ListModelsRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		m := items[i]

		capabilities := make([]any, 0, len(m.Capabilities))
		for _, capability := range m.Capabilities {
			capabilities = append(capabilities, string(capability))
		}
		fineTune, err := convert.JsonToDict(m.FineTuneDetails)
		if err != nil {
			return nil, err
		}

		mqlModel, err := CreateResource(o.MqlRuntime, "oci.ai.generativeAi.model", map[string]*llx.RawData{
			"id":                  llx.StringDataPtr(m.Id),
			"name":                llx.StringDataPtr(m.DisplayName),
			"compartmentID":       llx.StringDataPtr(m.CompartmentId),
			"type":                llx.StringData(string(m.Type)),
			"capabilities":        llx.ArrayData(capabilities, types.String),
			"vendor":              llx.StringDataPtr(m.Vendor),
			"version":             llx.StringDataPtr(m.Version),
			"baseModelID":         llx.StringDataPtr(m.BaseModelId),
			"fineTuneDetails":     llx.DictData(fineTune),
			"isLongTermSupported": llx.BoolDataPtr(m.IsLongTermSupported),
			"state":               llx.StringData(string(m.LifecycleState)),
			"lifecycleDetails":    llx.StringDataPtr(m.LifecycleDetails),
			"timeDeprecated":      sdkTimeData(m.TimeDeprecated),
			"created":             sdkTimeData(m.TimeCreated),
			"freeformTags":        llx.MapData(strMapToAny(m.FreeformTags), types.String),
			"definedTags":         llx.MapData(definedTagsToAny(m.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		mqlModelTyped := mqlModel.(*mqlOciAiGenerativeAiModel)
		mqlModelTyped.cacheBaseModelID = stringValue(m.BaseModelId)
		res = append(res, mqlModelTyped)
	}
	return res, nil
}

type mqlOciAiGenerativeAiModelInternal struct {
	cacheBaseModelID string
}

func initOciAiGenerativeAiModel(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return findOciGenerativeAiByID(runtime, args, "oci.ai.generativeAi.model", (*mqlOciAiGenerativeAi).GetModels)
}

func (o *mqlOciAiGenerativeAiModel) id() (string, error) {
	return "oci.ai.generativeAi.model/" + o.Id.Data, nil
}

func (o *mqlOciAiGenerativeAiModel) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.CompartmentID.Data, &o.Compartment)
}

func (o *mqlOciAiGenerativeAiModel) baseModel() (*mqlOciAiGenerativeAiModel, error) {
	return resolveOciGenerativeAiModel(o.MqlRuntime, o.cacheBaseModelID, &o.BaseModel)
}

// ----- endpoints -----

func (o *mqlOciAiGenerativeAi) endpoints() ([]any, error) {
	return o.listRegional(o.fetchEndpoints)
}

func (o *mqlOciAiGenerativeAi) fetchEndpoints(svc *generativeai.GenerativeAiClient, region string, compartmentID string) ([]any, error) {
	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]generativeai.EndpointSummary, *string, error) {
		resp, err := svc.ListEndpoints(ctx, generativeai.ListEndpointsRequest{
			CompartmentId: common.String(compartmentID),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return resp.Items, resp.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	res := make([]any, 0, len(items))
	for i := range items {
		e := items[i]

		if conn.Filters.IsFilteredOutByTags(e.FreeformTags, e.DefinedTags) {
			continue
		}

		var cmEnabled, piEnabled, piiEnabled bool
		var cmMode, piMode, piiMode string
		if cfg := e.ContentModerationConfig; cfg != nil {
			cmEnabled = boolValue(cfg.IsEnabled)
			cmMode = string(cfg.Mode)
		}
		if cfg := e.PromptInjectionConfig; cfg != nil {
			piEnabled = boolValue(cfg.IsEnabled)
			piMode = string(cfg.Mode)
		}
		if cfg := e.PiiDetectionConfig; cfg != nil {
			piiEnabled = boolValue(cfg.IsEnabled)
			piiMode = string(cfg.Mode)
		}

		mqlEndpoint, err := CreateResource(o.MqlRuntime, "oci.ai.generativeAi.endpoint", map[string]*llx.RawData{
			"id":                            llx.StringDataPtr(e.Id),
			"name":                          llx.StringDataPtr(e.DisplayName),
			"compartmentID":                 llx.StringDataPtr(e.CompartmentId),
			"modelID":                       llx.StringDataPtr(e.ModelId),
			"dedicatedAiClusterID":          llx.StringDataPtr(e.DedicatedAiClusterId),
			"generativeAiPrivateEndpointID": llx.StringDataPtr(e.GenerativeAiPrivateEndpointId),
			"description":                   llx.StringDataPtr(e.Description),
			"contentModerationEnabled":      llx.BoolData(cmEnabled),
			"contentModerationMode":         llx.StringData(cmMode),
			"promptInjectionEnabled":        llx.BoolData(piEnabled),
			"promptInjectionMode":           llx.StringData(piMode),
			"piiDetectionEnabled":           llx.BoolData(piiEnabled),
			"piiDetectionMode":              llx.StringData(piiMode),
			"state":                         llx.StringData(string(e.LifecycleState)),
			"lifecycleDetails":              llx.StringDataPtr(e.LifecycleDetails),
			"created":                       sdkTimeData(e.TimeCreated),
			"timeUpdated":                   sdkTimeData(e.TimeUpdated),
			"freeformTags":                  llx.MapData(strMapToAny(e.FreeformTags), types.String),
			"definedTags":                   llx.MapData(definedTagsToAny(e.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		mqlEndpointTyped := mqlEndpoint.(*mqlOciAiGenerativeAiEndpoint)
		mqlEndpointTyped.cacheModelID = stringValue(e.ModelId)
		mqlEndpointTyped.cacheDedicatedAiClusterID = stringValue(e.DedicatedAiClusterId)
		mqlEndpointTyped.cacheRegion = region
		res = append(res, mqlEndpointTyped)
	}
	return res, nil
}

type mqlOciAiGenerativeAiEndpointInternal struct {
	cacheModelID              string
	cacheDedicatedAiClusterID string
	cacheRegion               string
}

func initOciAiGenerativeAiEndpoint(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// When selected as a discovered asset there is no "id" arg; fall back to
	// the connection's platform id and pull the endpoint OCID from it, matching
	// the oci-ai-generativeai-endpoint platform emitted during discovery.
	if ociArgString(args, "id") == "" {
		conn := runtime.Connection.(*connection.OciConnection)
		if conn.Conf == nil || conn.Conf.PlatformId == "" {
			return args, nil, nil
		}
		parsed, ok := parseOciObjectPlatformID(conn.Conf.PlatformId)
		if !ok || parsed.service != "generativeai" || parsed.objectType != "endpoint" {
			return args, nil, nil
		}
		if args == nil {
			args = map[string]*llx.RawData{}
		}
		args["id"] = llx.StringData(parsed.id)
	}
	return findOciGenerativeAiByID(runtime, args, "oci.ai.generativeAi.endpoint", (*mqlOciAiGenerativeAi).GetEndpoints)
}

func (o *mqlOciAiGenerativeAiEndpoint) id() (string, error) {
	return "oci.ai.generativeAi.endpoint/" + o.Id.Data, nil
}

func (o *mqlOciAiGenerativeAiEndpoint) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.CompartmentID.Data, &o.Compartment)
}

func (o *mqlOciAiGenerativeAiEndpoint) model() (*mqlOciAiGenerativeAiModel, error) {
	return resolveOciGenerativeAiModel(o.MqlRuntime, o.cacheModelID, &o.Model)
}

func (o *mqlOciAiGenerativeAiEndpoint) dedicatedAiCluster() (*mqlOciAiGenerativeAiDedicatedAiCluster, error) {
	if o.cacheDedicatedAiClusterID == "" {
		o.DedicatedAiCluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.ai.generativeAi.dedicatedAiCluster", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheDedicatedAiClusterID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciAiGenerativeAiDedicatedAiCluster), nil
}

// ----- helpers -----

// findOciGenerativeAiByID powers the init functions for Generative AI
// resources: it lists the requested collection and returns the entry whose id
// matches the "id" argument, so a resource can be selected directly by OCID.
func findOciGenerativeAiByID(runtime *plugin.Runtime, args map[string]*llx.RawData, resourceName string, list func(svc *mqlOciAiGenerativeAi) *plugin.TValue[[]any]) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idVal := ociArgString(args, "id")
	if idVal == "" {
		return args, nil, nil
	}
	obj, err := CreateResource(runtime, "oci.ai.generativeAi", nil)
	if err != nil {
		return nil, nil, err
	}
	svc := obj.(*mqlOciAiGenerativeAi)
	items := list(svc)
	if items.Error != nil {
		return nil, nil, items.Error
	}
	for _, raw := range items.Data {
		res := raw.(plugin.Resource)
		if idField, ok := raw.(interface{ GetId() *plugin.TValue[string] }); ok && idField.GetId().Data == idVal {
			return args, res, nil
		}
	}
	return nil, nil, errors.New(resourceName + " not found: " + idVal)
}

// resolveOciGenerativeAiModel resolves a typed model resource from a model
// OCID. Returns (nil, nil) and marks the field null when the OCID is empty.
func resolveOciGenerativeAiModel(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOciAiGenerativeAiModel]) (*mqlOciAiGenerativeAiModel, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(runtime, "oci.ai.generativeAi.model", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciAiGenerativeAiModel), nil
}
