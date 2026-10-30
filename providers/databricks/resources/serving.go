// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/databricks/databricks-sdk-go/service/serving"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// mqlDatabricksServingEndpointInternal caches the source endpoint so the served
// entities can be built without re-listing, and memoizes the endpoint detail
// lookup that backs routeOptimized and the AI Gateway configuration (both are
// omitted from the list response).
type mqlDatabricksServingEndpointInternal struct {
	endpoint      serving.ServingEndpoint
	detailFetched atomic.Bool
	detail        *serving.ServingEndpointDetailed
	detailLock    sync.Mutex
}

func (r *mqlDatabricks) servingEndpoints() ([]any, error) {
	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	endpoints, err := ws.ServingEndpoints.ListAll(context.Background())
	if err != nil {
		return nil, err
	}

	out := []any{}
	for i := range endpoints {
		ep := endpoints[i]
		state := ""
		configUpdate := ""
		if ep.State != nil {
			state = string(ep.State.Ready)
			configUpdate = string(ep.State.ConfigUpdate)
		}

		tags, err := convert.JsonToDictSlice(ep.Tags)
		if err != nil {
			return nil, err
		}

		res, err := CreateResource(r.MqlRuntime, "databricks.servingEndpoint", map[string]*llx.RawData{
			"__id":           llx.StringData("databricks.servingEndpoint/" + ep.Name),
			"name":           llx.StringData(ep.Name),
			"id":             llx.StringData(ep.Id),
			"state":          llx.StringData(state),
			"configUpdate":   llx.StringData(configUpdate),
			"creator":        llx.StringData(ep.Creator),
			"task":           llx.StringData(ep.Task),
			"budgetPolicyId": llx.StringData(ep.BudgetPolicyId),
			"description":    llx.StringData(ep.Description),
			"createdAt":      llx.TimeDataPtr(epochMsTime(ep.CreationTimestamp)),
			"updatedAt":      llx.TimeDataPtr(epochMsTime(ep.LastUpdatedTimestamp)),
			"tags":           llx.ArrayData(tags, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		mqlEp := res.(*mqlDatabricksServingEndpoint)
		mqlEp.endpoint = ep
		out = append(out, res)
	}
	return out, nil
}

// servedEntities maps each entity in the endpoint's active config to a resource,
// flattening the external-model and foundation-model identity while never
// exposing any provider credential.
func (r *mqlDatabricksServingEndpoint) servedEntities() ([]any, error) {
	out := []any{}
	cfg := r.endpoint.Config
	if cfg == nil {
		return out, nil
	}

	for i := range cfg.ServedEntities {
		e := cfg.ServedEntities[i]

		foundationModelName := ""
		if e.FoundationModel != nil {
			foundationModelName = e.FoundationModel.Name
		}

		externalModelProvider := ""
		externalModelName := ""
		externalModelTask := ""
		if e.ExternalModel != nil {
			externalModelProvider = string(e.ExternalModel.Provider)
			externalModelName = e.ExternalModel.Name
			externalModelTask = e.ExternalModel.Task
		}

		res, err := CreateResource(r.MqlRuntime, "databricks.servingEndpoint.servedEntity", map[string]*llx.RawData{
			"__id":                  llx.StringData("databricks.servingEndpoint/" + r.Name.Data + "/servedEntity/" + e.Name),
			"name":                  llx.StringData(e.Name),
			"entityName":            llx.StringData(e.EntityName),
			"entityVersion":         llx.StringData(e.EntityVersion),
			"foundationModelName":   llx.StringData(foundationModelName),
			"externalModelProvider": llx.StringData(externalModelProvider),
			"externalModelName":     llx.StringData(externalModelName),
			"externalModelTask":     llx.StringData(externalModelTask),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// aiGateway maps the endpoint's AI Gateway governance to a resource, or null
// when the endpoint has no AI Gateway configured.
func (r *mqlDatabricksServingEndpoint) aiGateway() (*mqlDatabricksServingEndpointGatewayConfig, error) {
	detail, err := r.endpointDetail()
	if err != nil {
		return nil, err
	}
	var gw *serving.AiGatewayConfig
	if detail != nil {
		gw = detail.AiGateway
	}
	if gw == nil {
		r.AiGateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	usageTrackingEnabled := false
	if gw.UsageTrackingConfig != nil {
		usageTrackingEnabled = gw.UsageTrackingConfig.Enabled
	}

	inferenceTableEnabled := false
	inferenceTableCatalog := ""
	inferenceTableSchema := ""
	inferenceTableTablePrefix := ""
	if gw.InferenceTableConfig != nil {
		inferenceTableEnabled = gw.InferenceTableConfig.Enabled
		inferenceTableCatalog = gw.InferenceTableConfig.CatalogName
		inferenceTableSchema = gw.InferenceTableConfig.SchemaName
		inferenceTableTablePrefix = gw.InferenceTableConfig.TableNamePrefix
	}

	fallbackEnabled := false
	if gw.FallbackConfig != nil {
		fallbackEnabled = gw.FallbackConfig.Enabled
	}

	guardrails, err := convert.JsonToDict(gw.Guardrails)
	if err != nil {
		return nil, err
	}
	rateLimits, err := convert.JsonToDictSlice(gw.RateLimits)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(r.MqlRuntime, "databricks.servingEndpoint.gatewayConfig", map[string]*llx.RawData{
		"__id":                      llx.StringData("databricks.servingEndpoint/" + r.Name.Data + "/aiGateway"),
		"usageTrackingEnabled":      llx.BoolData(usageTrackingEnabled),
		"inferenceTableEnabled":     llx.BoolData(inferenceTableEnabled),
		"inferenceTableCatalog":     llx.StringData(inferenceTableCatalog),
		"inferenceTableSchema":      llx.StringData(inferenceTableSchema),
		"inferenceTableTablePrefix": llx.StringData(inferenceTableTablePrefix),
		"guardrails":                llx.DictData(guardrails),
		"rateLimits":                llx.ArrayData(rateLimits, types.Dict),
		"fallbackEnabled":           llx.BoolData(fallbackEnabled),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatabricksServingEndpointGatewayConfig), nil
}

// routeOptimized reports whether route optimization is enabled. The list
// response omits this flag, so it is read on demand from the endpoint detail
// and memoized.
func (r *mqlDatabricksServingEndpoint) routeOptimized() (bool, error) {
	detail, err := r.endpointDetail()
	if err != nil {
		return false, err
	}
	if detail == nil {
		return false, nil
	}
	return detail.RouteOptimized, nil
}

func (r *mqlDatabricksServingEndpoint) endpointDetail() (*serving.ServingEndpointDetailed, error) {
	if r.detailFetched.Load() {
		return r.detail, nil
	}
	r.detailLock.Lock()
	defer r.detailLock.Unlock()
	if r.detailFetched.Load() {
		return r.detail, nil
	}

	ws, err := workspaceClient(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	detail, err := ws.ServingEndpoints.GetByName(context.Background(), r.Name.Data)
	if err != nil {
		return nil, err
	}
	r.detail = detail
	r.detailFetched.Store(true)
	return r.detail, nil
}
