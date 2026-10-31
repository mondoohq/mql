// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/oracle/oci-go-sdk/v65/generativeaiagent"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciAi) id() (string, error) {
	return "oci.ai", nil
}

func (o *mqlOciAiAgents) id() (string, error) {
	return "oci.ai.agents", nil
}

// ----- agents -----

func (o *mqlOciAiAgents) agents() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci generative ai agents with region %s", region)

			svc, err := conn.GenerativeAiAgentClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]generativeaiagent.AgentSummary, *string, error) {
				response, err := svc.ListAgents(ctx, generativeaiagent.ListAgentsRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				if ociRegionServiceUnavailable(err) {
					log.Debug().Str("region", region).Msg("generative ai agents not available in region, skipping")
					return []any{}, nil
				}
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				a := items[i]

				llmConfig, err := convert.JsonToDict(a.LlmConfig)
				if err != nil {
					return nil, err
				}

				mqlAgent, err := CreateResource(o.MqlRuntime, "oci.ai.agents.agent", map[string]*llx.RawData{
					"id":               llx.StringDataPtr(a.Id),
					"name":             llx.StringDataPtr(a.DisplayName),
					"compartmentID":    llx.StringDataPtr(a.CompartmentId),
					"description":      llx.StringDataPtr(a.Description),
					"welcomeMessage":   llx.StringDataPtr(a.WelcomeMessage),
					"llmConfig":        llx.DictData(llmConfig),
					"state":            llx.StringData(string(a.LifecycleState)),
					"lifecycleDetails": llx.StringDataPtr(a.LifecycleDetails),
					"created":          sdkTimeData(a.TimeCreated),
					"timeUpdated":      sdkTimeData(a.TimeUpdated),
					"freeformTags":     llx.MapData(strMapToAny(a.FreeformTags), types.String),
					"definedTags":      llx.MapData(definedTagsToAny(a.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				mqlAgent.(*mqlOciAiAgentsAgent).cacheKnowledgeBaseIDs = a.KnowledgeBaseIds
				res = append(res, mqlAgent)
			}
			return res, nil
		})
}

func initOciAiAgentsAgent(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idVal := ociArgString(args, "id")
	if idVal == "" {
		return args, nil, nil
	}
	obj, err := CreateResource(runtime, "oci.ai.agents", nil)
	if err != nil {
		return nil, nil, err
	}
	list := obj.(*mqlOciAiAgents).GetAgents()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		a := raw.(*mqlOciAiAgentsAgent)
		if a.Id.Data == idVal {
			return args, a, nil
		}
	}
	return nil, nil, errors.New("oci.ai.agents.agent not found: " + idVal)
}

func (o *mqlOciAiAgentsAgent) id() (string, error) {
	return "oci.ai.agents.agent/" + o.Id.Data, nil
}

func (o *mqlOciAiAgentsAgent) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.CompartmentID.Data, &o.Compartment)
}

type mqlOciAiAgentsAgentInternal struct {
	cacheKnowledgeBaseIDs []string
}

func (o *mqlOciAiAgentsAgent) knowledgeBases() ([]any, error) {
	return resolveOciAiKnowledgeBases(o.MqlRuntime, o.cacheKnowledgeBaseIDs)
}

// ----- agent endpoints -----

func (o *mqlOciAiAgents) agentEndpoints() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.GenerativeAiAgentClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]generativeaiagent.AgentEndpointSummary, *string, error) {
				response, err := svc.ListAgentEndpoints(ctx, generativeaiagent.ListAgentEndpointsRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				if ociRegionServiceUnavailable(err) {
					return []any{}, nil
				}
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				e := items[i]

				var modInput, modOutput bool
				if e.ContentModerationConfig != nil {
					modInput = boolValue(e.ContentModerationConfig.ShouldEnableOnInput)
					modOutput = boolValue(e.ContentModerationConfig.ShouldEnableOnOutput)
				}
				guardrail, err := convert.JsonToDict(e.GuardrailConfig)
				if err != nil {
					return nil, err
				}
				var idleTimeout int64
				if e.SessionConfig != nil {
					idleTimeout = intValue(e.SessionConfig.IdleTimeoutInSeconds)
				}
				var humanInput *bool
				if e.HumanInputConfig != nil {
					humanInput = e.HumanInputConfig.ShouldEnableHumanInput
				}
				output := ociAgentEndpointOutput(e.OutputConfig)

				mqlEndpoint, err := CreateResource(o.MqlRuntime, "oci.ai.agents.endpoint", map[string]*llx.RawData{
					"id":                          llx.StringDataPtr(e.Id),
					"name":                        llx.StringDataPtr(e.DisplayName),
					"compartmentID":               llx.StringDataPtr(e.CompartmentId),
					"agentID":                     llx.StringDataPtr(e.AgentId),
					"description":                 llx.StringDataPtr(e.Description),
					"contentModerationOnInput":    llx.BoolData(modInput),
					"contentModerationOnOutput":   llx.BoolData(modOutput),
					"guardrailConfig":             llx.DictData(guardrail),
					"sessionIdleTimeoutInSeconds": llx.IntData(idleTimeout),
					"sessionEnabled":              llx.BoolDataPtr(e.ShouldEnableSession),
					"traceEnabled":                llx.BoolDataPtr(e.ShouldEnableTrace),
					"citationEnabled":             llx.BoolDataPtr(e.ShouldEnableCitation),
					"multiLanguageEnabled":        llx.BoolDataPtr(e.ShouldEnableMultiLanguage),
					"humanInputEnabled":           llx.BoolDataPtr(humanInput),
					"outputPrefix":                llx.StringData(output.prefix),
					"outputRetentionInMinutes":    llx.IntDataPtr(output.retentionInMinutes),
					"metadata":                    llx.MapData(strMapToAny(e.Metadata), types.String),
					"state":                       llx.StringData(string(e.LifecycleState)),
					"lifecycleDetails":            llx.StringDataPtr(e.LifecycleDetails),
					"created":                     sdkTimeData(e.TimeCreated),
					"timeUpdated":                 sdkTimeData(e.TimeUpdated),
					"freeformTags":                llx.MapData(strMapToAny(e.FreeformTags), types.String),
					"definedTags":                 llx.MapData(definedTagsToAny(e.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				mqlEndpointTyped := mqlEndpoint.(*mqlOciAiAgentsEndpoint)
				mqlEndpointTyped.cacheAgentID = stringValue(e.AgentId)
				mqlEndpointTyped.cacheOutput = output
				mqlEndpointTyped.cacheRegion = region
				res = append(res, mqlEndpointTyped)
			}
			return res, nil
		})
}

type mqlOciAiAgentsEndpointInternal struct {
	cacheAgentID string
	cacheOutput  ociAgentOutput
	cacheRegion  string
}

func initOciAiAgentsEndpoint(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idVal := ociArgString(args, "id")
	if idVal == "" {
		return args, nil, nil
	}
	obj, err := CreateResource(runtime, "oci.ai.agents", nil)
	if err != nil {
		return nil, nil, err
	}
	list := obj.(*mqlOciAiAgents).GetAgentEndpoints()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		e := raw.(*mqlOciAiAgentsEndpoint)
		if e.Id.Data == idVal {
			return args, e, nil
		}
	}
	return nil, nil, errors.New("oci.ai.agents.endpoint not found: " + idVal)
}

func (o *mqlOciAiAgentsEndpoint) id() (string, error) {
	return "oci.ai.agents.endpoint/" + o.Id.Data, nil
}

func (o *mqlOciAiAgentsEndpoint) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.CompartmentID.Data, &o.Compartment)
}

func (o *mqlOciAiAgentsEndpoint) agent() (*mqlOciAiAgentsAgent, error) {
	return resolveOciAiAgent(o.MqlRuntime, o.cacheAgentID, &o.Agent)
}

// outputBucket resolves the Object Storage bucket the endpoint writes chat
// output to. GetBucket is regional; the output location names no region, so
// the bucket is looked up in the endpoint's own region.
func (o *mqlOciAiAgentsEndpoint) outputBucket() (*mqlOciObjectStorageBucket, error) {
	out := o.cacheOutput
	// Both parts are required: an empty namespace would build the cache key
	// "oci.objectStorage.bucket//<name>", shared by every such bucket.
	if out.namespace == "" || out.bucket == "" || o.cacheRegion == "" {
		o.OutputBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	regionRes, err := NewResource(o.MqlRuntime, "oci.region", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheRegion),
	})
	if err != nil {
		return nil, err
	}
	res, err := NewResource(o.MqlRuntime, "oci.objectStorage.bucket", map[string]*llx.RawData{
		"namespace": llx.StringData(out.namespace),
		"name":      llx.StringData(out.bucket),
		"region":    llx.ResourceData(regionRes, "oci.region"),
	})
	if err != nil {
		// The bucket can be deleted while the endpoint still names it.
		if ociReferentGone(err) {
			log.Debug().Str("bucket", out.bucket).Msg("agent endpoint output bucket no longer exists")
			o.OutputBucket.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlOciObjectStorageBucket), nil
}

// ociAgentOutput is where an agent endpoint persists chat output.
type ociAgentOutput struct {
	namespace          string
	bucket             string
	prefix             string
	retentionInMinutes *int
}

// ociAgentEndpointOutput extracts the Object Storage output location and the
// retention period from an agent endpoint's output configuration.
func ociAgentEndpointOutput(cfg *generativeaiagent.OutputConfig) ociAgentOutput {
	var res ociAgentOutput
	if cfg == nil {
		return res
	}
	res.retentionInMinutes = cfg.RetentionPeriodInMinutes
	switch loc := cfg.OutputLocation.(type) {
	case generativeaiagent.ObjectStoragePrefixOutputLocation:
		res.namespace = stringValue(loc.NamespaceName)
		res.bucket = stringValue(loc.BucketName)
		res.prefix = stringValue(loc.Prefix)
	case *generativeaiagent.ObjectStoragePrefixOutputLocation:
		if loc != nil {
			res.namespace = stringValue(loc.NamespaceName)
			res.bucket = stringValue(loc.BucketName)
			res.prefix = stringValue(loc.Prefix)
		}
	}
	return res
}

// ----- knowledge bases -----

func (o *mqlOciAiAgents) knowledgeBases() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.GenerativeAiAgentClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]generativeaiagent.KnowledgeBaseSummary, *string, error) {
				response, err := svc.ListKnowledgeBases(ctx, generativeaiagent.ListKnowledgeBasesRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				if ociRegionServiceUnavailable(err) {
					return []any{}, nil
				}
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				kb := items[i]

				mqlKb, err := CreateResource(o.MqlRuntime, "oci.ai.agents.knowledgeBase", map[string]*llx.RawData{
					"id":               llx.StringDataPtr(kb.Id),
					"name":             llx.StringDataPtr(kb.DisplayName),
					"compartmentID":    llx.StringDataPtr(kb.CompartmentId),
					"description":      llx.StringDataPtr(kb.Description),
					"state":            llx.StringData(string(kb.LifecycleState)),
					"lifecycleDetails": llx.StringDataPtr(kb.LifecycleDetails),
					"created":          sdkTimeData(kb.TimeCreated),
					"timeUpdated":      sdkTimeData(kb.TimeUpdated),
					"freeformTags":     llx.MapData(strMapToAny(kb.FreeformTags), types.String),
					"definedTags":      llx.MapData(definedTagsToAny(kb.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlKb)
			}
			return res, nil
		})
}

func initOciAiAgentsKnowledgeBase(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idVal := ociArgString(args, "id")
	if idVal == "" {
		return args, nil, nil
	}
	obj, err := CreateResource(runtime, "oci.ai.agents", nil)
	if err != nil {
		return nil, nil, err
	}
	list := obj.(*mqlOciAiAgents).GetKnowledgeBases()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		kb := raw.(*mqlOciAiAgentsKnowledgeBase)
		if kb.Id.Data == idVal {
			return args, kb, nil
		}
	}
	return nil, nil, errors.New("oci.ai.agents.knowledgeBase not found: " + idVal)
}

func (o *mqlOciAiAgentsKnowledgeBase) id() (string, error) {
	return "oci.ai.agents.knowledgeBase/" + o.Id.Data, nil
}

func (o *mqlOciAiAgentsKnowledgeBase) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.CompartmentID.Data, &o.Compartment)
}

// ----- data sources -----

func (o *mqlOciAiAgents) dataSources() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.GenerativeAiAgentClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]generativeaiagent.DataSourceSummary, *string, error) {
				response, err := svc.ListDataSources(ctx, generativeaiagent.ListDataSourcesRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				if ociRegionServiceUnavailable(err) {
					return []any{}, nil
				}
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				ds := items[i]

				mqlDs, err := CreateResource(o.MqlRuntime, "oci.ai.agents.dataSource", map[string]*llx.RawData{
					"id":               llx.StringDataPtr(ds.Id),
					"name":             llx.StringDataPtr(ds.DisplayName),
					"compartmentID":    llx.StringDataPtr(ds.CompartmentId),
					"knowledgeBaseID":  llx.StringDataPtr(ds.KnowledgeBaseId),
					"description":      llx.StringDataPtr(ds.Description),
					"state":            llx.StringData(string(ds.LifecycleState)),
					"lifecycleDetails": llx.StringDataPtr(ds.LifecycleDetails),
					"created":          sdkTimeData(ds.TimeCreated),
					"timeUpdated":      sdkTimeData(ds.TimeUpdated),
					"freeformTags":     llx.MapData(strMapToAny(ds.FreeformTags), types.String),
					"definedTags":      llx.MapData(definedTagsToAny(ds.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				mqlDsTyped := mqlDs.(*mqlOciAiAgentsDataSource)
				mqlDsTyped.cacheKnowledgeBaseID = stringValue(ds.KnowledgeBaseId)
				res = append(res, mqlDsTyped)
			}
			return res, nil
		})
}

type mqlOciAiAgentsDataSourceInternal struct {
	cacheKnowledgeBaseID string
}

func initOciAiAgentsDataSource(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idVal := ociArgString(args, "id")
	if idVal == "" {
		return args, nil, nil
	}
	obj, err := CreateResource(runtime, "oci.ai.agents", nil)
	if err != nil {
		return nil, nil, err
	}
	list := obj.(*mqlOciAiAgents).GetDataSources()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		ds := raw.(*mqlOciAiAgentsDataSource)
		if ds.Id.Data == idVal {
			return args, ds, nil
		}
	}
	return nil, nil, errors.New("oci.ai.agents.dataSource not found: " + idVal)
}

func (o *mqlOciAiAgentsDataSource) id() (string, error) {
	return "oci.ai.agents.dataSource/" + o.Id.Data, nil
}

func (o *mqlOciAiAgentsDataSource) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.CompartmentID.Data, &o.Compartment)
}

func (o *mqlOciAiAgentsDataSource) knowledgeBase() (*mqlOciAiAgentsKnowledgeBase, error) {
	if o.cacheKnowledgeBaseID == "" {
		o.KnowledgeBase.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(o.MqlRuntime, "oci.ai.agents.knowledgeBase", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheKnowledgeBaseID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciAiAgentsKnowledgeBase), nil
}

// ----- tools -----

func (o *mqlOciAiAgents) tools() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.GenerativeAiAgentClient(region)
			if err != nil {
				return nil, err
			}

			// ListTools requires an agentId, so list the agents of this
			// compartment and walk the tools of each one.
			agents, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]generativeaiagent.AgentSummary, *string, error) {
				response, err := svc.ListAgents(ctx, generativeaiagent.ListAgentsRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			var items []generativeaiagent.ToolSummary
			if err == nil {
				agentIDs := make([]string, 0, len(agents))
				for i := range agents {
					agentIDs = append(agentIDs, stringValue(agents[i].Id))
				}
				items, err = ociListAgentTools(ctx, agentIDs, func(ctx context.Context, agentID string, page *string) ([]generativeaiagent.ToolSummary, *string, error) {
					response, err := svc.ListTools(ctx, generativeaiagent.ListToolsRequest{
						AgentId: new(agentID),
						Page:    page,
					})
					if err != nil {
						return nil, nil, err
					}
					return response.Items, response.OpcNextPage, nil
				})
			}
			if err != nil {
				if ociRegionServiceUnavailable(err) {
					return []any{}, nil
				}
				return nil, err
			}

			res := make([]any, 0, len(items))
			for i := range items {
				t := items[i]

				toolConfig, err := convert.JsonToDict(t.ToolConfig)
				if err != nil {
					return nil, err
				}

				mqlTool, err := CreateResource(o.MqlRuntime, "oci.ai.agents.tool", map[string]*llx.RawData{
					"id":            llx.StringDataPtr(t.Id),
					"name":          llx.StringDataPtr(t.DisplayName),
					"compartmentID": llx.StringDataPtr(t.CompartmentId),
					"agentID":       llx.StringDataPtr(t.AgentId),
					"description":   llx.StringDataPtr(t.Description),
					"toolType":      llx.StringData(ociToolConfigType(toolConfig)),
					"toolConfig":    llx.DictData(toolConfig),
					"metadata":      llx.MapData(strMapToAny(t.Metadata), types.String),
					"state":         llx.StringData(string(t.LifecycleState)),
					"created":       sdkTimeData(t.TimeCreated),
					"timeUpdated":   sdkTimeData(t.TimeUpdated),
					"freeformTags":  llx.MapData(strMapToAny(t.FreeformTags), types.String),
					"definedTags":   llx.MapData(definedTagsToAny(t.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				mqlToolTyped := mqlTool.(*mqlOciAiAgentsTool)
				mqlToolTyped.cacheAgentID = stringValue(t.AgentId)
				mqlToolTyped.cacheSubnetID, mqlToolTyped.cacheKnowledgeBaseIDs = ociToolConfigRefs(t.ToolConfig)
				res = append(res, mqlToolTyped)
			}
			return res, nil
		})
}

// ociListAgentTools lists the tools of every agent, one paginated ListTools
// walk per agent. Agents with an empty id are skipped.
func ociListAgentTools(ctx context.Context, agentIDs []string, page func(ctx context.Context, agentID string, page *string) ([]generativeaiagent.ToolSummary, *string, error)) ([]generativeaiagent.ToolSummary, error) {
	tools := []generativeaiagent.ToolSummary{}
	for _, agentID := range agentIDs {
		if agentID == "" {
			continue
		}
		items, err := ociPaginate(ctx, func(ctx context.Context, cursor *string) ([]generativeaiagent.ToolSummary, *string, error) {
			return page(ctx, agentID, cursor)
		})
		if err != nil {
			return nil, err
		}
		tools = append(tools, items...)
	}
	return tools, nil
}

type mqlOciAiAgentsToolInternal struct {
	cacheAgentID          string
	cacheSubnetID         string
	cacheKnowledgeBaseIDs []string
}

func initOciAiAgentsTool(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idVal := ociArgString(args, "id")
	if idVal == "" {
		return args, nil, nil
	}
	obj, err := CreateResource(runtime, "oci.ai.agents", nil)
	if err != nil {
		return nil, nil, err
	}
	list := obj.(*mqlOciAiAgents).GetTools()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		t := raw.(*mqlOciAiAgentsTool)
		if t.Id.Data == idVal {
			return args, t, nil
		}
	}
	return nil, nil, errors.New("oci.ai.agents.tool not found: " + idVal)
}

func (o *mqlOciAiAgentsTool) id() (string, error) {
	return "oci.ai.agents.tool/" + o.Id.Data, nil
}

func (o *mqlOciAiAgentsTool) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.CompartmentID.Data, &o.Compartment)
}

func (o *mqlOciAiAgentsTool) agent() (*mqlOciAiAgentsAgent, error) {
	return resolveOciAiAgent(o.MqlRuntime, o.cacheAgentID, &o.Agent)
}

func (o *mqlOciAiAgentsTool) subnet() (*mqlOciNetworkSubnet, error) {
	return resolveOciSubnet(o.MqlRuntime, o.cacheSubnetID, &o.Subnet)
}

func (o *mqlOciAiAgentsTool) knowledgeBases() ([]any, error) {
	return resolveOciAiKnowledgeBases(o.MqlRuntime, o.cacheKnowledgeBaseIDs)
}

// ociToolConfigRefs extracts the resources a tool configuration points at:
// the subnet an HTTP endpoint tool calls out from, and the knowledge bases a
// RAG tool retrieves from. Other tool types reference neither.
func ociToolConfigRefs(cfg generativeaiagent.ToolConfig) (subnetID string, knowledgeBaseIDs []string) {
	var kbConfigs []generativeaiagent.KnowledgeBaseConfig
	switch c := cfg.(type) {
	case generativeaiagent.HttpEndpointToolConfig:
		subnetID = stringValue(c.SubnetId)
	case *generativeaiagent.HttpEndpointToolConfig:
		if c != nil {
			subnetID = stringValue(c.SubnetId)
		}
	case generativeaiagent.RagToolConfig:
		kbConfigs = c.KnowledgeBaseConfigs
	case *generativeaiagent.RagToolConfig:
		if c != nil {
			kbConfigs = c.KnowledgeBaseConfigs
		}
	}
	for _, kb := range kbConfigs {
		if id := stringValue(kb.KnowledgeBaseId); id != "" {
			knowledgeBaseIDs = append(knowledgeBaseIDs, id)
		}
	}
	return subnetID, knowledgeBaseIDs
}

// ----- helpers -----

// resolveOciAiAgent resolves a typed agent resource from an agent OCID. Returns
// (nil, nil) and marks the field as null when the OCID is empty.
func resolveOciAiAgent(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOciAiAgentsAgent]) (*mqlOciAiAgentsAgent, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(runtime, "oci.ai.agents.agent", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOciAiAgentsAgent), nil
}

// resolveOciAiKnowledgeBases resolves knowledge base OCIDs through the
// cached knowledge base listing. An OCID the listing does not contain (a
// deleted knowledge base, or one in a compartment outside the scan) is
// skipped; a failure to list is returned.
func resolveOciAiKnowledgeBases(runtime *plugin.Runtime, ids []string) ([]any, error) {
	if len(ids) == 0 {
		return []any{}, nil
	}
	obj, err := CreateResource(runtime, "oci.ai.agents", nil)
	if err != nil {
		return nil, err
	}
	list := obj.(*mqlOciAiAgents).GetKnowledgeBases()
	if list.Error != nil {
		return nil, list.Error
	}
	return ociSelectByID(list.Data, ids), nil
}

// ociSelectByID returns the resources from items whose id is in ids, in the
// order of ids. Ids with no matching resource are skipped.
func ociSelectByID(items []any, ids []string) []any {
	byID := make(map[string]any, len(items))
	for _, raw := range items {
		if r, ok := raw.(interface{ GetId() *plugin.TValue[string] }); ok {
			byID[r.GetId().Data] = raw
		}
	}
	res := make([]any, 0, len(ids))
	for _, id := range ids {
		if r, ok := byID[id]; ok && id != "" {
			res = append(res, r)
		}
	}
	return res
}

// ociToolConfigType extracts the polymorphic tool-config discriminator
// (toolConfigType) from a tool configuration dict.
func ociToolConfigType(toolConfig any) string {
	m, ok := toolConfig.(map[string]any)
	if !ok {
		return ""
	}
	t, _ := m["toolConfigType"].(string)
	return t
}
