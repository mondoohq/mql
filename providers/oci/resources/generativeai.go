// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/oracle/oci-go-sdk/v65/generativeai"
	"github.com/rs/zerolog/log"
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
			CompartmentId: new(compartmentID),
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
			"id":                    llx.StringDataPtr(c.Id),
			"name":                  llx.StringDataPtr(c.DisplayName),
			"compartmentID":         llx.StringDataPtr(c.CompartmentId),
			"type":                  llx.StringData(string(c.Type)),
			"unitCount":             llx.IntDataPtr(c.UnitCount),
			"unitShape":             llx.StringData(string(c.UnitShape)),
			"capacity":              llx.DictData(capacity),
			"description":           llx.StringDataPtr(c.Description),
			"state":                 llx.StringData(string(c.LifecycleState)),
			"lifecycleDetails":      llx.StringDataPtr(c.LifecycleDetails),
			"capacityReservationID": llx.StringDataPtr(c.CapacityReservationId),
			"created":               sdkTimeData(c.TimeCreated),
			"timeUpdated":           sdkTimeData(c.TimeUpdated),
			"freeformTags":          llx.MapData(strMapToAny(c.FreeformTags), types.String),
			"definedTags":           llx.MapData(definedTagsToAny(c.DefinedTags), types.Any),
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
			CompartmentId: new(compartmentID),
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
			CompartmentId: new(compartmentID),
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
		mqlEndpointTyped.cachePrivateEndpointID = stringValue(e.GenerativeAiPrivateEndpointId)
		mqlEndpointTyped.cacheRegion = region
		res = append(res, mqlEndpointTyped)
	}
	return res, nil
}

type mqlOciAiGenerativeAiEndpointInternal struct {
	cacheModelID              string
	cacheDedicatedAiClusterID string
	cachePrivateEndpointID    string
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

func (o *mqlOciAiGenerativeAiEndpoint) privateEndpoint() (*mqlOciAiGenerativeAiPrivateEndpoint, error) {
	return resolveRef(o.MqlRuntime, "oci.ai.generativeAi.privateEndpoint", o.cachePrivateEndpointID, &o.PrivateEndpoint)
}

// ----- private endpoints -----

func (o *mqlOciAiGenerativeAi) privateEndpoints() ([]any, error) {
	return o.listRegional(o.fetchPrivateEndpoints)
}

func (o *mqlOciAiGenerativeAi) fetchPrivateEndpoints(svc *generativeai.GenerativeAiClient, region string, compartmentID string) ([]any, error) {
	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]generativeai.GenerativeAiPrivateEndpointSummary, *string, error) {
		resp, err := svc.ListGenerativeAiPrivateEndpoints(ctx, generativeai.ListGenerativeAiPrivateEndpointsRequest{
			CompartmentId: new(compartmentID),
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
		pe := items[i]
		mqlPe, err := CreateResource(o.MqlRuntime, "oci.ai.generativeAi.privateEndpoint", map[string]*llx.RawData{
			"id":               llx.StringDataPtr(pe.Id),
			"name":             llx.StringDataPtr(pe.DisplayName),
			"compartmentID":    llx.StringDataPtr(pe.CompartmentId),
			"description":      llx.StringDataPtr(pe.Description),
			"fqdn":             llx.StringDataPtr(pe.Fqdn),
			"privateIp":        llx.StringDataPtr(pe.PrivateEndpointIp),
			"isAllowOnDemand":  llx.BoolDataPtr(pe.IsAllowOnDemand),
			"resourceType":     llx.StringData(string(pe.ResourceType)),
			"state":            llx.StringData(string(pe.LifecycleState)),
			"lifecycleDetails": llx.StringDataPtr(pe.LifecycleDetails),
			"created":          sdkTimeData(pe.TimeCreated),
			"timeUpdated":      sdkTimeData(pe.TimeUpdated),
			"freeformTags":     llx.MapData(strMapToAny(pe.FreeformTags), types.String),
			"definedTags":      llx.MapData(definedTagsToAny(pe.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		mqlPeTyped := mqlPe.(*mqlOciAiGenerativeAiPrivateEndpoint)
		mqlPeTyped.cacheSubnetID = stringValue(pe.SubnetId)
		mqlPeTyped.cacheRegion = region
		res = append(res, mqlPeTyped)
	}
	return res, nil
}

type mqlOciAiGenerativeAiPrivateEndpointInternal struct {
	cacheSubnetID string
	cacheRegion   string
}

func initOciAiGenerativeAiPrivateEndpoint(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return findOciGenerativeAiByID(runtime, args, "oci.ai.generativeAi.privateEndpoint", (*mqlOciAiGenerativeAi).GetPrivateEndpoints)
}

func (o *mqlOciAiGenerativeAiPrivateEndpoint) id() (string, error) {
	return "oci.ai.generativeAi.privateEndpoint/" + o.Id.Data, nil
}

func (o *mqlOciAiGenerativeAiPrivateEndpoint) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.CompartmentID.Data, &o.Compartment)
}

func (o *mqlOciAiGenerativeAiPrivateEndpoint) subnet() (*mqlOciNetworkSubnet, error) {
	return resolveOciSubnet(o.MqlRuntime, o.cacheSubnetID, &o.Subnet)
}

// networkSecurityGroups reads the NSGs from the private endpoint's detail
// record: the list API's summary does not carry them.
func (o *mqlOciAiGenerativeAiPrivateEndpoint) networkSecurityGroups() ([]any, error) {
	region := o.cacheRegion
	if region == "" {
		region = ociRegionFromOCID(o.Id.Data)
	}
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	svc, err := conn.GenerativeAiClient(region)
	if err != nil {
		return nil, err
	}
	resp, err := svc.GetGenerativeAiPrivateEndpoint(context.Background(), generativeai.GetGenerativeAiPrivateEndpointRequest{
		GenerativeAiPrivateEndpointId: new(o.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return resolveOciNetworkSecurityGroups(o.MqlRuntime, resp.NsgIds), nil
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

// ----- hosted applications -----

func (o *mqlOciAiGenerativeAi) hostedApplications() ([]any, error) {
	return o.listRegional(o.fetchHostedApplications)
}

func (o *mqlOciAiGenerativeAi) fetchHostedApplications(svc *generativeai.GenerativeAiClient, region string, compartmentID string) ([]any, error) {
	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]generativeai.HostedApplicationSummary, *string, error) {
		resp, err := svc.ListHostedApplications(ctx, generativeai.ListHostedApplicationsRequest{
			CompartmentId: new(compartmentID),
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
		a := items[i]
		mqlApp, err := createOciResourceInCompartment(o.MqlRuntime, "oci.ai.generativeAi.hostedApplication", stringValue(a.CompartmentId), map[string]*llx.RawData{
			"id":           llx.StringDataPtr(a.Id),
			"name":         llx.StringDataPtr(a.DisplayName),
			"description":  llx.StringDataPtr(a.Description),
			"state":        llx.StringData(string(a.LifecycleState)),
			"created":      sdkTimeData(a.TimeCreated),
			"timeUpdated":  sdkTimeData(a.TimeUpdated),
			"freeformTags": llx.MapData(strMapToAny(a.FreeformTags), types.String),
			"definedTags":  llx.MapData(definedTagsToAny(a.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		mqlAppTyped := mqlApp.(*mqlOciAiGenerativeAiHostedApplication)
		mqlAppTyped.cacheRegion = region
		res = append(res, mqlAppTyped)
	}
	return res, nil
}

type mqlOciAiGenerativeAiHostedApplicationInternal struct {
	ociCompartmentRef
	cacheRegion string
	details     ociLazy[*ociHostedApplicationDetails]
}

func initOciAiGenerativeAiHostedApplication(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return findOciGenerativeAiByID(runtime, args, "oci.ai.generativeAi.hostedApplication", (*mqlOciAiGenerativeAi).GetHostedApplications)
}

func (o *mqlOciAiGenerativeAiHostedApplication) id() (string, error) {
	return "oci.ai.generativeAi.hostedApplication/" + o.Id.Data, nil
}

func (o *mqlOciAiGenerativeAiHostedApplication) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciAiGenerativeAiHostedApplication) region() string {
	if o.cacheRegion != "" {
		return o.cacheRegion
	}
	return ociRegionFromOCID(o.Id.Data)
}

// getDetails reads the hosted application record. The list API returns a
// summary without the authentication, networking, and environment settings,
// so every field built from those shares this one GetHostedApplication call.
func (o *mqlOciAiGenerativeAiHostedApplication) getDetails() (*ociHostedApplicationDetails, error) {
	return o.details.get(func() (*ociHostedApplicationDetails, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		svc, err := conn.GenerativeAiClient(o.region())
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetHostedApplication(context.Background(), generativeai.GetHostedApplicationRequest{
			HostedApplicationId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return ociHostedApplicationDetailsFrom(&resp.HostedApplication), nil
	})
}

func (o *mqlOciAiGenerativeAiHostedApplication) lifecycleDetails() (string, error) {
	d, err := o.getDetails()
	if err != nil {
		return "", err
	}
	return d.lifecycleDetails, nil
}

func (o *mqlOciAiGenerativeAiHostedApplication) inboundAuthType() (string, error) {
	d, err := o.getDetails()
	if err != nil {
		return "", err
	}
	return d.inboundAuthType, nil
}

func (o *mqlOciAiGenerativeAiHostedApplication) endpointMode() (string, error) {
	d, err := o.getDetails()
	if err != nil {
		return "", err
	}
	return d.endpointMode, nil
}

func (o *mqlOciAiGenerativeAiHostedApplication) privateEndpoint() (*mqlOciAiGenerativeAiPrivateEndpoint, error) {
	d, err := o.getDetails()
	if err != nil {
		return nil, err
	}
	return resolveRef(o.MqlRuntime, "oci.ai.generativeAi.privateEndpoint", d.privateEndpointID, &o.PrivateEndpoint)
}

func (o *mqlOciAiGenerativeAiHostedApplication) outboundNetworkMode() (string, error) {
	d, err := o.getDetails()
	if err != nil {
		return "", err
	}
	return d.outboundNetworkMode, nil
}

func (o *mqlOciAiGenerativeAiHostedApplication) subnet() (*mqlOciNetworkSubnet, error) {
	d, err := o.getDetails()
	if err != nil {
		return nil, err
	}
	return resolveOciSubnet(o.MqlRuntime, d.subnetID, &o.Subnet)
}

func (o *mqlOciAiGenerativeAiHostedApplication) networkSecurityGroups() ([]any, error) {
	d, err := o.getDetails()
	if err != nil {
		return nil, err
	}
	return resolveOciNetworkSecurityGroups(o.MqlRuntime, d.nsgIDs), nil
}

func (o *mqlOciAiGenerativeAiHostedApplication) publicAccessPathPatterns() ([]any, error) {
	d, err := o.getDetails()
	if err != nil {
		return nil, err
	}
	return stringsToAny(d.publicAccessPathPatterns), nil
}

func (o *mqlOciAiGenerativeAiHostedApplication) applicationEndpoint() (string, error) {
	d, err := o.getDetails()
	if err != nil {
		return "", err
	}
	return d.applicationEndpoint, nil
}

func (o *mqlOciAiGenerativeAiHostedApplication) environmentVariableNames() ([]any, error) {
	d, err := o.getDetails()
	if err != nil {
		return nil, err
	}
	return stringsToAny(d.environmentVariableNames), nil
}

func (o *mqlOciAiGenerativeAiHostedApplication) vaultEnvironmentVariableNames() ([]any, error) {
	d, err := o.getDetails()
	if err != nil {
		return nil, err
	}
	return stringsToAny(d.vaultEnvironmentVariableNames), nil
}

func (o *mqlOciAiGenerativeAiHostedApplication) isPublic() (bool, error) {
	d, err := o.getDetails()
	if err != nil {
		return false, err
	}
	return d.isPublic(), nil
}

func (o *mqlOciAiGenerativeAiHostedApplication) hostedDeployments() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	svc, err := conn.GenerativeAiClient(o.region())
	if err != nil {
		return nil, err
	}
	compartmentID := o.cacheCompartmentID
	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]generativeai.HostedDeploymentSummary, *string, error) {
		resp, err := svc.ListHostedDeployments(ctx, generativeai.ListHostedDeploymentsRequest{
			CompartmentId: new(compartmentID),
			ApplicationId: new(o.Id.Data),
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
		d := items[i]
		art := ociHostedDeploymentArtifactFrom(d.ActiveArtifact)
		mqlDeployment, err := CreateResource(o.MqlRuntime, "oci.ai.generativeAi.hostedDeployment", map[string]*llx.RawData{
			"id":                         llx.StringDataPtr(d.Id),
			"state":                      llx.StringData(string(d.LifecycleState)),
			"activeArtifactType":         llx.StringData(art.artifactType),
			"activeArtifactStatus":       llx.StringData(art.status),
			"activeArtifactContainerUri": llx.StringData(art.containerURI),
			"activeArtifactTag":          llx.StringData(art.tag),
			"activeArtifactVulnerabilityScanRequired": llx.BoolDataPtr(art.vulnerabilityScanRequired),
			"created":      sdkTimeData(d.TimeCreated),
			"timeUpdated":  sdkTimeData(d.TimeUpdated),
			"freeformTags": llx.MapData(strMapToAny(d.FreeformTags), types.String),
			"definedTags":  llx.MapData(definedTagsToAny(d.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlDeployment)
	}
	return res, nil
}

func (o *mqlOciAiGenerativeAiHostedDeployment) id() (string, error) {
	return "oci.ai.generativeAi.hostedDeployment/" + o.Id.Data, nil
}

// ociHostedApplicationDetails is the part of a hosted application record the
// schema reads. Environment variables are reduced to their names here so a
// value, which can be a plaintext secret, never leaves this function.
type ociHostedApplicationDetails struct {
	lifecycleDetails              string
	inboundAuthType               string
	endpointMode                  string
	privateEndpointID             string
	outboundNetworkMode           string
	subnetID                      string
	nsgIDs                        []string
	publicAccessPathPatterns      []string
	applicationEndpoint           string
	environmentVariableNames      []string
	vaultEnvironmentVariableNames []string
}

func ociHostedApplicationDetailsFrom(app *generativeai.HostedApplication) *ociHostedApplicationDetails {
	d := &ociHostedApplicationDetails{
		lifecycleDetails:              stringValue(app.LifecycleDetails),
		applicationEndpoint:           stringValue(app.ApplicationEndpoint),
		publicAccessPathPatterns:      app.PublicAccessPathPatterns,
		environmentVariableNames:      []string{},
		vaultEnvironmentVariableNames: []string{},
	}
	if app.InboundAuthConfig != nil {
		d.inboundAuthType = string(app.InboundAuthConfig.InboundAuthConfigType)
	}
	if nc := app.NetworkingConfig; nc != nil {
		if in := nc.InboundNetworkingConfig; in != nil {
			d.endpointMode = string(in.EndpointMode)
			d.privateEndpointID = stringValue(in.PrivateEndpointId)
		}
		if out := nc.OutboundNetworkingConfig; out != nil {
			d.outboundNetworkMode = string(out.NetworkMode)
			d.subnetID = stringValue(out.CustomSubnetId)
			d.nsgIDs = out.NsgIds
		}
	}
	for _, v := range app.EnvironmentVariables {
		name := stringValue(v.Name)
		if name == "" {
			continue
		}
		d.environmentVariableNames = append(d.environmentVariableNames, name)
		if v.Type == generativeai.EnvironmentVariableTypeVault {
			d.vaultEnvironmentVariableNames = append(d.vaultEnvironmentVariableNames, name)
		}
	}
	return d
}

// isPublic reports an application anyone on the internet can call: a public
// endpoint that asks for no authentication.
func (d *ociHostedApplicationDetails) isPublic() bool {
	return d.endpointMode == string(generativeai.InboundNetworkingConfigEndpointModePublic) &&
		d.inboundAuthType == string(generativeai.InboundAuthConfigInboundAuthConfigTypeNoAuthConfig)
}

// ociHostedDeploymentArtifact is the active artifact of a hosted deployment.
type ociHostedDeploymentArtifact struct {
	artifactType              string
	status                    string
	containerURI              string
	tag                       string
	vulnerabilityScanRequired *bool
}

func ociHostedDeploymentArtifactFrom(a generativeai.Artifact) ociHostedDeploymentArtifact {
	var res ociHostedDeploymentArtifact
	if a == nil {
		return res
	}
	res.status = string(a.GetStatus())
	res.vulnerabilityScanRequired = a.GetIsVulnerabilityScanRequired()
	switch v := a.(type) {
	case generativeai.SingleDockerArtifact:
		res.artifactType = string(generativeai.ArtifactArtifactTypeSimpleDockerArtifact)
		res.containerURI = stringValue(v.ContainerUri)
		res.tag = stringValue(v.Tag)
	case *generativeai.SingleDockerArtifact:
		res.artifactType = string(generativeai.ArtifactArtifactTypeSimpleDockerArtifact)
		res.containerURI = stringValue(v.ContainerUri)
		res.tag = stringValue(v.Tag)
	}
	return res
}

// ----- API keys -----

func (o *mqlOciAiGenerativeAi) apiKeys() ([]any, error) {
	return o.listRegional(o.fetchApiKeys)
}

func (o *mqlOciAiGenerativeAi) fetchApiKeys(svc *generativeai.GenerativeAiClient, _ string, compartmentID string) ([]any, error) {
	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]generativeai.ApiKeySummary, *string, error) {
		resp, err := svc.ListApiKeys(ctx, generativeai.ListApiKeysRequest{
			CompartmentId: new(compartmentID),
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
		k := items[i]
		apiKeyID := stringValue(k.Id)

		keys := make([]any, 0, len(k.Keys))
		for j := range k.Keys {
			mqlKey, err := CreateResource(o.MqlRuntime, "oci.ai.generativeAi.apiKey.key", ociApiKeyItemArgs(apiKeyID, &k.Keys[j]))
			if err != nil {
				return nil, err
			}
			keys = append(keys, mqlKey)
		}

		mqlApiKey, err := createOciResourceInCompartment(o.MqlRuntime, "oci.ai.generativeAi.apiKey", stringValue(k.CompartmentId), map[string]*llx.RawData{
			"id":               llx.StringData(apiKeyID),
			"name":             llx.StringDataPtr(k.DisplayName),
			"description":      llx.StringDataPtr(k.Description),
			"state":            llx.StringData(string(k.LifecycleState)),
			"lifecycleDetails": llx.StringDataPtr(k.LifecycleDetails),
			"keys":             llx.ArrayData(keys, types.Resource("oci.ai.generativeAi.apiKey.key")),
			"created":          sdkTimeData(k.TimeCreated),
			"timeUpdated":      sdkTimeData(k.TimeUpdated),
			"freeformTags":     llx.MapData(strMapToAny(k.FreeformTags), types.String),
			"definedTags":      llx.MapData(definedTagsToAny(k.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlApiKey)
	}
	return res, nil
}

// ociApiKeyItemArgs builds one key of an API key. The key value and its mask
// are deliberately left out: the mask's format is not documented, so it may
// reveal more of the key than a prefix.
func ociApiKeyItemArgs(apiKeyID string, item *generativeai.ApiKeyItem) map[string]*llx.RawData {
	name := stringValue(item.KeyName)
	return map[string]*llx.RawData{
		"__id":            llx.StringData(apiKeyID + "/" + name),
		"name":            llx.StringData(name),
		"state":           llx.StringData(string(item.State)),
		"created":         sdkTimeData(item.TimeCreated),
		"timeExpiry":      sdkTimeData(item.TimeExpiry),
		"timeActivated":   sdkTimeData(item.TimeActivated),
		"timeDeactivated": sdkTimeData(item.TimeDeactivated),
		"timeRevoked":     sdkTimeData(item.TimeRevoked),
		"timeLastUsed":    sdkTimeData(item.TimeLastUsed),
	}
}

type mqlOciAiGenerativeAiApiKeyInternal struct {
	ociCompartmentRef
}

func (o *mqlOciAiGenerativeAiApiKey) id() (string, error) {
	return "oci.ai.generativeAi.apiKey/" + o.Id.Data, nil
}

func (o *mqlOciAiGenerativeAiApiKey) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// ----- projects -----

func (o *mqlOciAiGenerativeAi) projects() ([]any, error) {
	return o.listRegional(o.fetchProjects)
}

func (o *mqlOciAiGenerativeAi) fetchProjects(svc *generativeai.GenerativeAiClient, region string, compartmentID string) ([]any, error) {
	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]generativeai.GenerativeAiProjectSummary, *string, error) {
		resp, err := svc.ListGenerativeAiProjects(ctx, generativeai.ListGenerativeAiProjectsRequest{
			CompartmentId: new(compartmentID),
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
		p := items[i]
		mqlProject, err := createOciResourceInCompartment(o.MqlRuntime, "oci.ai.generativeAi.project", stringValue(p.CompartmentId), map[string]*llx.RawData{
			"id":               llx.StringDataPtr(p.Id),
			"name":             llx.StringDataPtr(p.DisplayName),
			"description":      llx.StringDataPtr(p.Description),
			"state":            llx.StringData(string(p.LifecycleState)),
			"lifecycleDetails": llx.StringDataPtr(p.LifecycleDetails),
			"created":          sdkTimeData(p.TimeCreated),
			"timeUpdated":      sdkTimeData(p.TimeUpdated),
			"freeformTags":     llx.MapData(strMapToAny(p.FreeformTags), types.String),
			"definedTags":      llx.MapData(definedTagsToAny(p.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		mqlProjectTyped := mqlProject.(*mqlOciAiGenerativeAiProject)
		mqlProjectTyped.cacheRegion = region
		res = append(res, mqlProjectTyped)
	}
	return res, nil
}

type mqlOciAiGenerativeAiProjectInternal struct {
	ociCompartmentRef
	cacheRegion string
	details     ociLazy[*ociGenerativeAiProjectDetails]
}

func (o *mqlOciAiGenerativeAiProject) id() (string, error) {
	return "oci.ai.generativeAi.project/" + o.Id.Data, nil
}

func (o *mqlOciAiGenerativeAiProject) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// getDetails reads the project record: the list API's summary carries none of
// the conversation, memory, or sandbox settings.
func (o *mqlOciAiGenerativeAiProject) getDetails() (*ociGenerativeAiProjectDetails, error) {
	return o.details.get(func() (*ociGenerativeAiProjectDetails, error) {
		region := o.cacheRegion
		if region == "" {
			region = ociRegionFromOCID(o.Id.Data)
		}
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		svc, err := conn.GenerativeAiClient(region)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetGenerativeAiProject(context.Background(), generativeai.GetGenerativeAiProjectRequest{
			GenerativeAiProjectId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return ociGenerativeAiProjectDetailsFrom(&resp.GenerativeAiProject), nil
	})
}

func (o *mqlOciAiGenerativeAiProject) responsesRetentionInHours() (int64, error) {
	d, err := o.getDetails()
	if err != nil {
		return 0, err
	}
	if d.responsesRetentionInHours == nil {
		o.ResponsesRetentionInHours.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *d.responsesRetentionInHours, nil
}

func (o *mqlOciAiGenerativeAiProject) conversationsRetentionInHours() (int64, error) {
	d, err := o.getDetails()
	if err != nil {
		return 0, err
	}
	if d.conversationsRetentionInHours == nil {
		o.ConversationsRetentionInHours.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *d.conversationsRetentionInHours, nil
}

func (o *mqlOciAiGenerativeAiProject) shortTermMemoryOptimizationEnabled() (bool, error) {
	d, err := o.getDetails()
	if err != nil {
		return false, err
	}
	return d.shortTermMemoryOptimizationEnabled, nil
}

func (o *mqlOciAiGenerativeAiProject) sandboxEnabled() (bool, error) {
	d, err := o.getDetails()
	if err != nil {
		return false, err
	}
	return d.sandboxEnabled, nil
}

func (o *mqlOciAiGenerativeAiProject) sandboxPersistenceEnabled() (bool, error) {
	d, err := o.getDetails()
	if err != nil {
		return false, err
	}
	return d.sandboxPersistenceEnabled, nil
}

func (o *mqlOciAiGenerativeAiProject) sandboxOutboundNetworkMode() (string, error) {
	d, err := o.getDetails()
	if err != nil {
		return "", err
	}
	return d.sandboxOutboundNetworkMode, nil
}

func (o *mqlOciAiGenerativeAiProject) sandboxNetworkPolicyMode() (string, error) {
	d, err := o.getDetails()
	if err != nil {
		return "", err
	}
	if d.sandboxNetworkPolicyMode == "" {
		o.SandboxNetworkPolicyMode.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return d.sandboxNetworkPolicyMode, nil
}

func (o *mqlOciAiGenerativeAiProject) sandboxSubnet() (*mqlOciNetworkSubnet, error) {
	d, err := o.getDetails()
	if err != nil {
		return nil, err
	}
	return resolveOciSubnet(o.MqlRuntime, d.sandboxSubnetID, &o.SandboxSubnet)
}

func (o *mqlOciAiGenerativeAiProject) sandboxNetworkSecurityGroups() ([]any, error) {
	d, err := o.getDetails()
	if err != nil {
		return nil, err
	}
	return resolveOciNetworkSecurityGroups(o.MqlRuntime, d.sandboxNsgIDs), nil
}

func (o *mqlOciAiGenerativeAiProject) sandboxCredentialProfileLabels() ([]any, error) {
	d, err := o.getDetails()
	if err != nil {
		return nil, err
	}
	return stringsToAny(d.sandboxCredentialProfileLabels), nil
}

// ociGenerativeAiProjectDetails is the part of a project record the schema
// reads. Credential profiles are reduced to their labels; their injection
// rules name the secrets to inject and are not read.
type ociGenerativeAiProjectDetails struct {
	responsesRetentionInHours          *int64
	conversationsRetentionInHours      *int64
	shortTermMemoryOptimizationEnabled bool
	sandboxEnabled                     bool
	sandboxPersistenceEnabled          bool
	sandboxOutboundNetworkMode         string
	sandboxNetworkPolicyMode           string
	sandboxSubnetID                    string
	sandboxNsgIDs                      []string
	sandboxCredentialProfileLabels     []string
}

func ociGenerativeAiProjectDetailsFrom(p *generativeai.GenerativeAiProject) *ociGenerativeAiProjectDetails {
	d := &ociGenerativeAiProjectDetails{
		sandboxCredentialProfileLabels: []string{},
	}
	if c := p.ConversationConfig; c != nil {
		d.responsesRetentionInHours = intPtrToInt64Ptr(c.ResponsesRetentionInHours)
		d.conversationsRetentionInHours = intPtrToInt64Ptr(c.ConversationsRetentionInHours)
	}
	if c := p.ShortTermMemoryOptimizationConfig; c != nil {
		d.shortTermMemoryOptimizationEnabled = boolValue(c.IsEnabled)
	}
	sb := p.SandboxConfig
	if sb == nil {
		return d
	}
	d.sandboxEnabled = boolValue(sb.IsEnabled)
	d.sandboxPersistenceEnabled = boolValue(sb.IsPersistenceEnabled)
	for _, cp := range sb.CredentialProfiles {
		if label := stringValue(cp.Label); label != "" {
			d.sandboxCredentialProfileLabels = append(d.sandboxCredentialProfileLabels, label)
		}
	}
	switch out := sb.SandboxOutboundNetworkingConfig.(type) {
	case generativeai.ManagedSandboxOutboundNetworkingConfig:
		d.sandboxOutboundNetworkMode = string(generativeai.SandboxOutboundNetworkingConfigNetworkModeManaged)
		d.sandboxNetworkPolicyMode = ociSandboxNetworkPolicyMode(out.NetworkPolicy)
	case *generativeai.ManagedSandboxOutboundNetworkingConfig:
		d.sandboxOutboundNetworkMode = string(generativeai.SandboxOutboundNetworkingConfigNetworkModeManaged)
		d.sandboxNetworkPolicyMode = ociSandboxNetworkPolicyMode(out.NetworkPolicy)
	case generativeai.CustomSandboxOutboundNetworkingConfig:
		d.sandboxOutboundNetworkMode = string(generativeai.SandboxOutboundNetworkingConfigNetworkModeCustom)
		d.sandboxSubnetID = stringValue(out.SubnetId)
		d.sandboxNsgIDs = out.NsgIds
	case *generativeai.CustomSandboxOutboundNetworkingConfig:
		d.sandboxOutboundNetworkMode = string(generativeai.SandboxOutboundNetworkingConfigNetworkModeCustom)
		d.sandboxSubnetID = stringValue(out.SubnetId)
		d.sandboxNsgIDs = out.NsgIds
	}
	return d
}

func ociSandboxNetworkPolicyMode(p generativeai.SandboxNetworkPolicy) string {
	switch p.(type) {
	case generativeai.SandboxDenyAllNetworkPolicy, *generativeai.SandboxDenyAllNetworkPolicy:
		return string(generativeai.SandboxNetworkPolicyModeDenyAll)
	case generativeai.SandboxAllowAllNetworkPolicy, *generativeai.SandboxAllowAllNetworkPolicy:
		return string(generativeai.SandboxNetworkPolicyModeAllowAll)
	case generativeai.SandboxAllowNetworkPolicy, *generativeai.SandboxAllowNetworkPolicy:
		return string(generativeai.SandboxNetworkPolicyModeAllow)
	}
	return ""
}

func intPtrToInt64Ptr(i *int) *int64 {
	if i == nil {
		return nil
	}
	v := int64(*i)
	return &v
}

// ----- imported models -----

func (o *mqlOciAiGenerativeAi) importedModels() ([]any, error) {
	return o.listRegional(o.fetchImportedModels)
}

func (o *mqlOciAiGenerativeAi) fetchImportedModels(svc *generativeai.GenerativeAiClient, region string, compartmentID string) ([]any, error) {
	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]generativeai.ImportedModelSummary, *string, error) {
		resp, err := svc.ListImportedModels(ctx, generativeai.ListImportedModelsRequest{
			CompartmentId: new(compartmentID),
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
		for _, c := range m.Capabilities {
			capabilities = append(capabilities, string(c))
		}
		src := ociImportedModelSourceFrom(m.DataSource)

		mqlModel, err := createOciResourceInCompartment(o.MqlRuntime, "oci.ai.generativeAi.importedModel", stringValue(m.CompartmentId), map[string]*llx.RawData{
			"id":                  llx.StringDataPtr(m.Id),
			"name":                llx.StringDataPtr(m.DisplayName),
			"description":         llx.StringDataPtr(m.Description),
			"vendor":              llx.StringDataPtr(m.Vendor),
			"version":             llx.StringDataPtr(m.Version),
			"capabilities":        llx.ArrayData(capabilities, types.String),
			"sourceType":          llx.StringData(src.sourceType),
			"huggingFaceModelId":  llx.StringData(src.huggingFaceModelID),
			"huggingFaceBranch":   llx.StringData(src.huggingFaceBranch),
			"huggingFaceCommit":   llx.StringData(src.huggingFaceCommit),
			"objectStoragePrefix": llx.StringData(src.prefix),
			"state":               llx.StringData(string(m.LifecycleState)),
			"lifecycleDetails":    llx.StringDataPtr(m.LifecycleDetails),
			"created":             sdkTimeData(m.TimeCreated),
			"timeUpdated":         sdkTimeData(m.TimeUpdated),
			"freeformTags":        llx.MapData(strMapToAny(m.FreeformTags), types.String),
			"definedTags":         llx.MapData(definedTagsToAny(m.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		mqlModelTyped := mqlModel.(*mqlOciAiGenerativeAiImportedModel)
		mqlModelTyped.cacheSource = src
		mqlModelTyped.cacheRegion = region
		res = append(res, mqlModelTyped)
	}
	return res, nil
}

type mqlOciAiGenerativeAiImportedModelInternal struct {
	ociCompartmentRef
	cacheSource ociImportedModelSource
	cacheRegion string
}

func initOciAiGenerativeAiImportedModel(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return findOciGenerativeAiByID(runtime, args, "oci.ai.generativeAi.importedModel", (*mqlOciAiGenerativeAi).GetImportedModels)
}

func (o *mqlOciAiGenerativeAiImportedModel) id() (string, error) {
	return "oci.ai.generativeAi.importedModel/" + o.Id.Data, nil
}

func (o *mqlOciAiGenerativeAiImportedModel) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// bucket resolves the Object Storage bucket the weights were imported from.
// The data source names its region by full name, and only when it differs
// from the model's; without one the bucket is looked up in the model's region.
func (o *mqlOciAiGenerativeAiImportedModel) bucket() (*mqlOciObjectStorageBucket, error) {
	src := o.cacheSource
	// Both parts are required: an empty namespace would build the cache key
	// "oci.objectStorage.bucket//<name>", shared by every such bucket.
	if src.namespace == "" || src.bucket == "" {
		o.Bucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	regionID := o.cacheRegion
	if src.region != "" {
		items, err := ociServiceCollection(o.MqlRuntime, "oci", func(r plugin.Resource) *plugin.TValue[[]any] {
			return r.(*mqlOci).GetRegions()
		})
		if err != nil {
			return nil, err
		}
		region := ociRegionByName(items, src.region)
		if region == nil {
			log.Debug().Str("region", src.region).Msg("imported model bucket region not among the tenancy's subscriptions")
			o.Bucket.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		regionID = region.Id.Data
	}
	if regionID == "" {
		o.Bucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	regionRes, err := NewResource(o.MqlRuntime, "oci.region", map[string]*llx.RawData{
		"id": llx.StringData(regionID),
	})
	if err != nil {
		return nil, err
	}
	res, err := NewResource(o.MqlRuntime, "oci.objectStorage.bucket", map[string]*llx.RawData{
		"namespace": llx.StringData(src.namespace),
		"name":      llx.StringData(src.bucket),
		"region":    llx.ResourceData(regionRes, "oci.region"),
	})
	if err != nil {
		// The bucket can be deleted after the model was imported from it.
		if ociReferentGone(err) {
			log.Debug().Str("bucket", src.bucket).Msg("imported model source bucket no longer exists")
			o.Bucket.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlOciObjectStorageBucket), nil
}

// ociImportedModelSource is where an imported model's weights came from. The
// Hugging Face access token on the data source is not read.
type ociImportedModelSource struct {
	sourceType         string
	huggingFaceModelID string
	huggingFaceBranch  string
	huggingFaceCommit  string
	namespace          string
	bucket             string
	prefix             string
	region             string
}

func ociImportedModelSourceFrom(ds generativeai.ModelDataSource) ociImportedModelSource {
	var res ociImportedModelSource
	switch v := ds.(type) {
	case generativeai.HuggingFaceModel:
		res = ociHuggingFaceSource(&v)
	case *generativeai.HuggingFaceModel:
		res = ociHuggingFaceSource(v)
	case generativeai.ObjectStorageObject:
		res = ociObjectStorageSource(&v)
	case *generativeai.ObjectStorageObject:
		res = ociObjectStorageSource(v)
	}
	return res
}

func ociHuggingFaceSource(v *generativeai.HuggingFaceModel) ociImportedModelSource {
	return ociImportedModelSource{
		sourceType:         string(generativeai.ModelDataSourceSourceTypeHuggingFaceModel),
		huggingFaceModelID: stringValue(v.ModelId),
		huggingFaceBranch:  stringValue(v.Branch),
		huggingFaceCommit:  stringValue(v.Commit),
	}
}

func ociObjectStorageSource(v *generativeai.ObjectStorageObject) ociImportedModelSource {
	return ociImportedModelSource{
		sourceType: string(generativeai.ModelDataSourceSourceTypeObjectStorageObject),
		namespace:  stringValue(v.NamespaceName),
		bucket:     stringValue(v.BucketName),
		prefix:     stringValue(v.PrefixName),
		region:     stringValue(v.Region),
	}
}
