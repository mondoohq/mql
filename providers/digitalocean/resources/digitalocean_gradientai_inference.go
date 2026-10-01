// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
	"go.mondoo.com/mql/types"
)

// ----- Anthropic API keys -----

func (r *mqlDigitaloceanGradientai) anthropicApiKeys() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	keys, err := paginate(context.Background(), client.AgentPlatform.ListAnthropicAPIKeys)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(keys))
	for _, k := range keys {
		res, err := newMqlGradientaiAnthropicApiKey(r.MqlRuntime, k)
		if err != nil {
			return nil, err
		}
		if res != nil {
			all = append(all, res)
		}
	}
	return all, nil
}

func newMqlGradientaiAnthropicApiKey(runtime *plugin.Runtime, k *godo.AnthropicApiKeyInfo) (*mqlDigitaloceanGradientaiAnthropicApiKey, error) {
	if k == nil {
		return nil, nil
	}
	res, err := CreateResource(runtime, "digitalocean.gradientai.anthropicApiKey", map[string]*llx.RawData{
		"__id":      llx.StringData(k.Uuid),
		"uuid":      llx.StringData(k.Uuid),
		"name":      llx.StringData(k.Name),
		"createdBy": llx.StringData(k.CreatedBy),
		"createdAt": llx.TimeDataPtr(gradientaiTime(k.CreatedAt)),
		"updatedAt": llx.TimeDataPtr(gradientaiTime(k.UpdatedAt)),
		"deletedAt": llx.TimeDataPtr(gradientaiTime(k.DeletedAt)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDigitaloceanGradientaiAnthropicApiKey), nil
}

func (r *mqlDigitaloceanGradientaiAnthropicApiKey) agents() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	agents, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]*godo.Agent, *godo.Response, error) {
		return client.AgentPlatform.ListAgentsByAnthropicAPIKey(c, r.Uuid.Data, o)
	})
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(agents))
	for _, a := range agents {
		res, err := newMqlGradientaiAgent(r.MqlRuntime, a)
		if err != nil {
			return nil, err
		}
		if res != nil {
			all = append(all, res)
		}
	}
	return all, nil
}

// ----- OpenAI API keys -----

func (r *mqlDigitaloceanGradientai) openaiApiKeys() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	keys, err := paginate(context.Background(), client.AgentPlatform.ListOpenAIAPIKeys)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(keys))
	for _, k := range keys {
		res, err := newMqlGradientaiOpenaiApiKey(r.MqlRuntime, k)
		if err != nil {
			return nil, err
		}
		if res != nil {
			all = append(all, res)
		}
	}
	return all, nil
}

func newMqlGradientaiOpenaiApiKey(runtime *plugin.Runtime, k *godo.OpenAiApiKey) (*mqlDigitaloceanGradientaiOpenaiApiKey, error) {
	if k == nil {
		return nil, nil
	}
	res, err := CreateResource(runtime, "digitalocean.gradientai.openaiApiKey", map[string]*llx.RawData{
		"__id":      llx.StringData(k.Uuid),
		"uuid":      llx.StringData(k.Uuid),
		"name":      llx.StringData(k.Name),
		"createdBy": llx.StringData(k.CreatedBy),
		"createdAt": llx.TimeDataPtr(gradientaiTime(k.CreatedAt)),
		"updatedAt": llx.TimeDataPtr(gradientaiTime(k.UpdatedAt)),
		"deletedAt": llx.TimeDataPtr(gradientaiTime(k.DeletedAt)),
	})
	if err != nil {
		return nil, err
	}
	mqlKey := res.(*mqlDigitaloceanGradientaiOpenaiApiKey)
	mqlKey.cachedModels = k.Models
	return mqlKey, nil
}

type mqlDigitaloceanGradientaiOpenaiApiKeyInternal struct {
	cachedModels []*godo.Model
}

func (r *mqlDigitaloceanGradientaiOpenaiApiKey) models() ([]interface{}, error) {
	out := make([]interface{}, 0, len(r.cachedModels))
	for _, m := range r.cachedModels {
		res, err := newMqlGradientaiModel(r.MqlRuntime, m)
		if err != nil {
			return nil, err
		}
		if res != nil {
			out = append(out, res)
		}
	}
	return out, nil
}

func (r *mqlDigitaloceanGradientaiOpenaiApiKey) agents() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	agents, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]*godo.Agent, *godo.Response, error) {
		return client.AgentPlatform.ListAgentsByOpenAIAPIKey(c, r.Uuid.Data, o)
	})
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(agents))
	for _, a := range agents {
		res, err := newMqlGradientaiAgent(r.MqlRuntime, a)
		if err != nil {
			return nil, err
		}
		if res != nil {
			all = append(all, res)
		}
	}
	return all, nil
}

// ----- Dedicated inference endpoints -----

func (r *mqlDigitaloceanGradientai) dedicatedInferenceEndpoints() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	var all []interface{}
	opt := &godo.DedicatedInferenceListOptions{ListOptions: godo.ListOptions{PerPage: 200}}
	for {
		endpoints, resp, err := client.DedicatedInference.List(context.Background(), opt)
		if err != nil {
			return nil, err
		}
		for i := range endpoints {
			e := endpoints[i]
			modelIDs := make([]interface{}, len(e.ProviderModelID))
			for j, m := range e.ProviderModelID {
				modelIDs[j] = m
			}
			publicFQDN, privateFQDN := "", ""
			if e.Endpoints != nil {
				publicFQDN = e.Endpoints.PublicEndpointFQDN
				privateFQDN = e.Endpoints.PrivateEndpointFQDN
			}
			res, err := CreateResource(r.MqlRuntime, "digitalocean.gradientai.dedicatedInferenceEndpoint", map[string]*llx.RawData{
				"id":                  llx.StringData(e.ID),
				"name":                llx.StringData(e.Name),
				"region":              llx.StringData(e.Region),
				"status":              llx.StringData(e.Status),
				"providerModelIds":    llx.ArrayData(modelIDs, types.String),
				"publicEndpointFqdn":  llx.StringData(publicFQDN),
				"privateEndpointFqdn": llx.StringData(privateFQDN),
				"createdAt":           llx.TimeData(e.CreatedAt),
				"updatedAt":           llx.TimeData(e.UpdatedAt),
			})
			if err != nil {
				return nil, err
			}
			// Cache the VPC UUID so the typed vpc() accessor can resolve it
			// without a refetch.
			res.(*mqlDigitaloceanGradientaiDedicatedInferenceEndpoint).cacheVPCUUID = e.VPCUUID
			all = append(all, res)
		}
		if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			return nil, err
		}
		opt.Page = page + 1
	}
	return all, nil
}

// mqlDigitaloceanGradientaiDedicatedInferenceEndpointInternal caches the UUID
// of the VPC the endpoint runs in so the typed vpc() accessor can resolve it
// without a refetch.
type mqlDigitaloceanGradientaiDedicatedInferenceEndpointInternal struct {
	cacheVPCUUID string
}

func (r *mqlDigitaloceanGradientaiDedicatedInferenceEndpoint) id() (string, error) {
	return "digitalocean.gradientai.dedicatedInferenceEndpoint/" + r.Id.Data, nil
}

func (r *mqlDigitaloceanGradientaiDedicatedInferenceEndpoint) vpc() (*mqlDigitaloceanVpc, error) {
	return resolveVpcRef(r.MqlRuntime, &r.Vpc, r.cacheVPCUUID)
}

func (r *mqlDigitaloceanGradientaiDedicatedInferenceEndpoint) accelerators() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	var out []interface{}
	opt := &godo.DedicatedInferenceListAcceleratorsOptions{ListOptions: godo.ListOptions{PerPage: 200}}
	for {
		accelerators, resp, err := client.DedicatedInference.ListAccelerators(context.Background(), r.Id.Data, opt)
		if err != nil {
			return nil, err
		}
		for i := range accelerators {
			a := accelerators[i]
			res, err := CreateResource(r.MqlRuntime, "digitalocean.gradientai.dedicatedInferenceEndpoint.accelerator", map[string]*llx.RawData{
				"__id":      llx.StringData(r.Id.Data + "/" + a.ID),
				"id":        llx.StringData(a.ID),
				"name":      llx.StringData(a.Name),
				"slug":      llx.StringData(a.Slug),
				"status":    llx.StringData(a.Status),
				"createdAt": llx.TimeData(a.CreatedAt),
			})
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		if resp == nil || resp.Links == nil || resp.Links.IsLastPage() {
			break
		}
		page, err := resp.Links.CurrentPage()
		if err != nil {
			return nil, err
		}
		opt.Page = page + 1
	}
	return out, nil
}

func (r *mqlDigitaloceanGradientaiDedicatedInferenceEndpoint) tokens() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	tokens, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]godo.DedicatedInferenceToken, *godo.Response, error) {
		return client.DedicatedInference.ListTokens(c, r.Id.Data, o)
	})
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(tokens))
	for i := range tokens {
		t := tokens[i]
		// The token Value is a secret and is deliberately not surfaced.
		res, err := CreateResource(r.MqlRuntime, "digitalocean.gradientai.dedicatedInferenceEndpoint.token", map[string]*llx.RawData{
			"__id":      llx.StringData(r.Id.Data + "/" + t.ID),
			"id":        llx.StringData(t.ID),
			"name":      llx.StringData(t.Name),
			"isManaged": llx.BoolData(t.IsManaged),
			"createdAt": llx.TimeData(t.CreatedAt),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// ----- Batch inference jobs -----

func (r *mqlDigitaloceanGradientai) batchJobs() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	var all []interface{}
	// Batch jobs use cursor pagination: advance `After` with the response's
	// EndCursor until HasNextPage is false.
	opts := &godo.ListBatchesOptions{Limit: 200}
	for {
		resp, _, err := client.BatchInference.ListJobs(context.Background(), opts)
		if err != nil {
			return nil, err
		}
		if resp == nil {
			break
		}
		for i := range resp.Edges {
			b := resp.Edges[i].Node
			counts := map[string]interface{}{}
			if b.RequestCounts != nil {
				counts = map[string]interface{}{
					"total":     int64(b.RequestCounts.Total),
					"completed": int64(b.RequestCounts.Completed),
					"failed":    int64(b.RequestCounts.Failed),
				}
			}
			res, err := CreateResource(r.MqlRuntime, "digitalocean.gradientai.batchJob", map[string]*llx.RawData{
				"__id":              llx.StringData(b.BatchID),
				"batchId":           llx.StringData(b.BatchID),
				"provider":          llx.StringData(b.Provider),
				"fileId":            llx.StringData(b.FileID),
				"completionWindow":  llx.StringData(b.CompletionWindow),
				"status":            llx.StringData(b.Status),
				"requestId":         llx.StringData(b.RequestID),
				"resultAvailable":   llx.BoolData(b.ResultAvailable),
				"requestCounts":     llx.DictData(counts),
				"cancelRequestedAt": llx.TimeDataPtr(parseBatchTime(b.CancelRequestedAt)),
				"createdAt":         llx.TimeDataPtr(parseBatchTimeStr(b.CreatedAt)),
				"updatedAt":         llx.TimeDataPtr(parseBatchTimeStr(b.UpdatedAt)),
				"expiresAt":         llx.TimeDataPtr(parseBatchTime(b.ExpiresAt)),
			})
			if err != nil {
				return nil, err
			}
			all = append(all, res)
		}
		if !resp.PageInfo.HasNextPage || resp.PageInfo.EndCursor == "" {
			break
		}
		opts.After = resp.PageInfo.EndCursor
	}
	return all, nil
}

func parseBatchTimeStr(s string) *time.Time {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t
	}
	return nil
}

func parseBatchTime(s *string) *time.Time {
	if s == nil {
		return nil
	}
	return parseBatchTimeStr(*s)
}
