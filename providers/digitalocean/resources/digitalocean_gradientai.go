// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/digitalocean/connection"
	"go.mondoo.com/mql/types"
)

// gradientaiTime unwraps a godo *Timestamp into a *time.Time, returning
// nil when the timestamp is absent so the field resolves to null.
func gradientaiTime(t *godo.Timestamp) *time.Time {
	if t == nil {
		return nil
	}
	return &t.Time
}

// ----- GradientAI namespace -----

type mqlDigitaloceanGradientaiInternal struct {
	modelIndexOnce sync.Once
	modelIndex     map[string]*mqlDigitaloceanGradientaiModel
	modelIndexErr  error

	agentIndexOnce sync.Once
	agentIndex     map[string]*mqlDigitaloceanGradientaiAgent
	agentIndexErr  error

	kbIndexOnce sync.Once
	kbIndex     map[string]*mqlDigitaloceanGradientaiKnowledgeBase
	kbIndexErr  error
}

func (r *mqlDigitaloceanGradientai) id() (string, error) {
	return "digitalocean.gradientai", nil
}

func (r *mqlDigitalocean) gradientai() (*mqlDigitaloceanGradientai, error) {
	res, err := CreateResource(r.MqlRuntime, "digitalocean.gradientai", map[string]*llx.RawData{
		"__id": llx.StringData("digitalocean.gradientai"),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDigitaloceanGradientai), nil
}

func parentGradientai(runtime *plugin.Runtime) (*mqlDigitaloceanGradientai, error) {
	res, err := CreateResource(runtime, "digitalocean.gradientai", map[string]*llx.RawData{
		"__id": llx.StringData("digitalocean.gradientai"),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDigitaloceanGradientai), nil
}

func (r *mqlDigitaloceanGradientai) modelByUUID(uuid string) (*mqlDigitaloceanGradientaiModel, error) {
	r.modelIndexOnce.Do(func() {
		models := r.GetModels()
		if models.Error != nil {
			r.modelIndexErr = models.Error
			return
		}
		idx := make(map[string]*mqlDigitaloceanGradientaiModel, len(models.Data))
		for _, m := range models.Data {
			mm := m.(*mqlDigitaloceanGradientaiModel)
			idx[mm.Uuid.Data] = mm
		}
		r.modelIndex = idx
	})
	if r.modelIndexErr != nil {
		return nil, r.modelIndexErr
	}
	return r.modelIndex[uuid], nil
}

func (r *mqlDigitaloceanGradientai) agentByUUID(uuid string) (*mqlDigitaloceanGradientaiAgent, error) {
	r.agentIndexOnce.Do(func() {
		agents := r.GetAgents()
		if agents.Error != nil {
			r.agentIndexErr = agents.Error
			return
		}
		idx := make(map[string]*mqlDigitaloceanGradientaiAgent, len(agents.Data))
		for _, a := range agents.Data {
			ma := a.(*mqlDigitaloceanGradientaiAgent)
			idx[ma.Uuid.Data] = ma
		}
		r.agentIndex = idx
	})
	if r.agentIndexErr != nil {
		return nil, r.agentIndexErr
	}
	return r.agentIndex[uuid], nil
}

func (r *mqlDigitaloceanGradientai) knowledgeBaseByUUID(uuid string) (*mqlDigitaloceanGradientaiKnowledgeBase, error) {
	r.kbIndexOnce.Do(func() {
		kbs := r.GetKnowledgeBases()
		if kbs.Error != nil {
			r.kbIndexErr = kbs.Error
			return
		}
		idx := make(map[string]*mqlDigitaloceanGradientaiKnowledgeBase, len(kbs.Data))
		for _, k := range kbs.Data {
			mk := k.(*mqlDigitaloceanGradientaiKnowledgeBase)
			idx[mk.Uuid.Data] = mk
		}
		r.kbIndex = idx
	})
	if r.kbIndexErr != nil {
		return nil, r.kbIndexErr
	}
	return r.kbIndex[uuid], nil
}

// ----- Agents -----

type mqlDigitaloceanGradientaiAgentInternal struct {
	cachedModel        *godo.Model
	cachedKnowledgeB   []*godo.KnowledgeBase
	cachedGuardrails   []*godo.AgentGuardrail
	cachedFunctions    []*godo.AgentFunction
	cachedAnthropicKey *godo.AnthropicApiKeyInfo
	cachedOpenAIKey    *godo.OpenAiApiKey
	childUUIDs         []string
	parentUUIDs        []string
	// cacheVPCUUID holds the UUID of the VPC the agent runs in so the typed
	// vpc() accessor can resolve it without a refetch.
	cacheVPCUUID string
}

func (r *mqlDigitaloceanGradientai) agents() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	agents, err := paginate(context.Background(), client.AgentPlatform.ListAgents)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(agents))
	for _, a := range agents {
		if a != nil && skipGradientaiAgent(conn.Filters.General, a) {
			continue
		}
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

// newMqlGradientaiAgent builds an agent resource from a godo Agent. It
// returns (nil, nil) for a nil input; every caller iterates a list and
// skips nil results, so it is never used as a single-resource accessor
// that would need StateIsNull bookkeeping.
func newMqlGradientaiAgent(runtime *plugin.Runtime, a *godo.Agent) (*mqlDigitaloceanGradientaiAgent, error) {
	if a == nil {
		return nil, nil
	}

	egressIPs := make([]interface{}, len(a.VPCEgressIPs))
	for i, ip := range a.VPCEgressIPs {
		egressIPs[i] = ip
	}
	tags := make([]interface{}, len(a.Tags))
	for i, t := range a.Tags {
		tags[i] = t
	}

	chatbot := map[string]interface{}{}
	if a.ChatBot != nil {
		chatbot = map[string]interface{}{
			"name":            a.ChatBot.Name,
			"primaryColor":    a.ChatBot.PrimaryColor,
			"secondaryColor":  a.ChatBot.SecondaryColor,
			"startingMessage": a.ChatBot.StartingMessage,
			"logo":            a.ChatBot.Logo,
		}
	}

	deploymentName, deploymentStatus, deploymentVisibility, deploymentURL, deploymentUUID := "", "", "", "", ""
	if a.Deployment != nil {
		deploymentName = a.Deployment.Name
		deploymentStatus = a.Deployment.Status
		deploymentVisibility = a.Deployment.Visibility
		deploymentURL = a.Deployment.Url
		deploymentUUID = a.Deployment.Uuid
	}

	res, err := CreateResource(runtime, "digitalocean.gradientai.agent", map[string]*llx.RawData{
		"__id":                    llx.StringData(a.Uuid),
		"uuid":                    llx.StringData(a.Uuid),
		"name":                    llx.StringData(a.Name),
		"description":             llx.StringData(a.Description),
		"region":                  llx.StringData(a.Region),
		"instruction":             llx.StringData(a.Instruction),
		"temperature":             llx.FloatData(a.Temperature),
		"topP":                    llx.FloatData(a.TopP),
		"maxTokens":               llx.IntData(int64(a.MaxTokens)),
		"k":                       llx.IntData(int64(a.K)),
		"retrievalMethod":         llx.StringData(a.RetrievalMethod),
		"provideCitations":        llx.BoolData(a.ProvideCitations),
		"conversationLogsEnabled": llx.BoolData(a.ConversationLogsEnabled),
		"ifCase":                  llx.StringData(a.IfCase),
		"routeUuid":               llx.StringData(a.RouteUuid),
		"routeName":               llx.StringData(a.RouteName),
		"url":                     llx.StringData(a.Url),
		"userId":                  llx.StringData(a.UserId),
		"versionHash":             llx.StringData(a.VersionHash),
		"projectId":               llx.StringData(a.ProjectId),
		"vpcEgressIps":            llx.ArrayData(egressIPs, types.String),
		"tags":                    llx.ArrayData(tags, types.String),
		"deploymentName":          llx.StringData(deploymentName),
		"deploymentStatus":        llx.StringData(deploymentStatus),
		"deploymentVisibility":    llx.StringData(deploymentVisibility),
		"deploymentUrl":           llx.StringData(deploymentURL),
		"deploymentUuid":          llx.StringData(deploymentUUID),
		"chatbot":                 llx.DictData(chatbot),
		"createdAt":               llx.TimeDataPtr(gradientaiTime(a.CreatedAt)),
		"updatedAt":               llx.TimeDataPtr(gradientaiTime(a.UpdatedAt)),
	})
	if err != nil {
		return nil, err
	}

	agent := res.(*mqlDigitaloceanGradientaiAgent)
	agent.cacheVPCUUID = a.VPCUuid
	agent.cachedModel = a.Model
	agent.cachedKnowledgeB = a.KnowledgeBases
	agent.cachedGuardrails = a.Guardrails
	agent.cachedFunctions = a.Functions
	agent.cachedAnthropicKey = a.AnthropicApiKey
	agent.cachedOpenAIKey = a.OpenAiApiKey
	for _, c := range a.ChildAgents {
		if c != nil {
			agent.childUUIDs = append(agent.childUUIDs, c.Uuid)
		}
	}
	for _, p := range a.ParentAgents {
		if p != nil {
			agent.parentUUIDs = append(agent.parentUUIDs, p.Uuid)
		}
	}
	return agent, nil
}

// initDigitaloceanGradientaiAgent resolves a single GradientAI agent. It
// binds the agent selected by an explicit uuid argument, or - when the
// connection is scoped to a discovered digitalocean-gradientai-agent
// asset - the agent whose uuid the discovery step stamped on the
// connection options. Without either, the resource has nothing to bind
// to and returns an error.
func initDigitaloceanGradientaiAgent(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.DigitaloceanConnection)
	uuid := stringArg(args, "uuid")
	if uuid == "" {
		uuid = conn.Conf.Options[connection.OptionGradientaiAgent]
	}
	if uuid == "" {
		return nil, nil, errors.New("digitalocean.gradientai.agent requires a uuid or a connected digitalocean-gradientai-agent asset")
	}
	agent, _, err := conn.Client().AgentPlatform.GetAgent(context.Background(), uuid)
	if err != nil {
		return nil, nil, err
	}
	// GetAgent returns the decoded root's field, so a 200 carrying no agent
	// yields a nil agent and a nil error. Passing it on hands the runtime a
	// typed nil, which is not == nil once widened to plugin.Resource: the
	// runtime accepts it and panics reading its id.
	if agent == nil {
		return nil, nil, fmt.Errorf("digitalocean.gradientai.agent with uuid %q not found", uuid)
	}
	res, err := newMqlGradientaiAgent(runtime, agent)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlDigitaloceanGradientaiAgent) model() (*mqlDigitaloceanGradientaiModel, error) {
	if r.cachedModel == nil {
		r.Model.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlGradientaiModel(r.MqlRuntime, r.cachedModel)
}

func (r *mqlDigitaloceanGradientaiAgent) knowledgeBases() ([]interface{}, error) {
	out := make([]interface{}, 0, len(r.cachedKnowledgeB))
	for _, kb := range r.cachedKnowledgeB {
		mkb, err := newMqlGradientaiKnowledgeBase(r.MqlRuntime, kb)
		if err != nil {
			return nil, err
		}
		if mkb != nil {
			out = append(out, mkb)
		}
	}
	return out, nil
}

func (r *mqlDigitaloceanGradientaiAgent) childAgents() ([]interface{}, error) {
	return agentsByUUIDs(r.MqlRuntime, r.childUUIDs)
}

func (r *mqlDigitaloceanGradientaiAgent) parentAgents() ([]interface{}, error) {
	return agentsByUUIDs(r.MqlRuntime, r.parentUUIDs)
}

func agentsByUUIDs(runtime *plugin.Runtime, uuids []string) ([]interface{}, error) {
	if len(uuids) == 0 {
		return []interface{}{}, nil
	}
	parent, err := parentGradientai(runtime)
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, 0, len(uuids))
	for _, uuid := range uuids {
		agent, err := parent.agentByUUID(uuid)
		if err != nil {
			return nil, err
		}
		if agent != nil {
			out = append(out, agent)
		}
	}
	return out, nil
}

func (r *mqlDigitaloceanGradientaiAgent) project() (*mqlDigitaloceanProject, error) {
	return projectRef(r.MqlRuntime, r.ProjectId.Data, &r.Project)
}

func (r *mqlDigitaloceanGradientaiAgent) vpc() (*mqlDigitaloceanVpc, error) {
	return resolveVpcRef(r.MqlRuntime, &r.Vpc, r.cacheVPCUUID)
}

func (r *mqlDigitaloceanGradientaiAgent) anthropicApiKey() (*mqlDigitaloceanGradientaiAnthropicApiKey, error) {
	if r.cachedAnthropicKey == nil {
		r.AnthropicApiKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlGradientaiAnthropicApiKey(r.MqlRuntime, r.cachedAnthropicKey)
}

func (r *mqlDigitaloceanGradientaiAgent) openaiApiKey() (*mqlDigitaloceanGradientaiOpenaiApiKey, error) {
	if r.cachedOpenAIKey == nil {
		r.OpenaiApiKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlGradientaiOpenaiApiKey(r.MqlRuntime, r.cachedOpenAIKey)
}

func (r *mqlDigitaloceanGradientaiAgent) guardrails() ([]interface{}, error) {
	out := make([]interface{}, 0, len(r.cachedGuardrails))
	for _, g := range r.cachedGuardrails {
		if g == nil {
			continue
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.gradientai.agent.guardrail", map[string]*llx.RawData{
			"__id":            llx.StringData(g.Uuid),
			"uuid":            llx.StringData(g.Uuid),
			"agentUuid":       llx.StringData(g.AgentUuid),
			"name":            llx.StringData(g.Name),
			"type":            llx.StringData(g.Type),
			"description":     llx.StringData(g.Description),
			"defaultResponse": llx.StringData(g.DefaultResponse),
			"priority":        llx.IntData(int64(g.Priority)),
			"isAttached":      llx.BoolData(g.IsAttached),
			"isDefault":       llx.BoolData(g.IsDefault),
			"createdAt":       llx.TimeDataPtr(gradientaiTime(g.CreatedAt)),
			"updatedAt":       llx.TimeDataPtr(gradientaiTime(g.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDigitaloceanGradientaiAgent) functions() ([]interface{}, error) {
	out := make([]interface{}, 0, len(r.cachedFunctions))
	for _, f := range r.cachedFunctions {
		if f == nil {
			continue
		}
		// The function's API key is a secret and is deliberately not surfaced.
		res, err := CreateResource(r.MqlRuntime, "digitalocean.gradientai.agent.function", map[string]*llx.RawData{
			"__id":          llx.StringData(f.Uuid),
			"uuid":          llx.StringData(f.Uuid),
			"name":          llx.StringData(f.Name),
			"description":   llx.StringData(f.Description),
			"faasName":      llx.StringData(f.FaasName),
			"faasNamespace": llx.StringData(f.FaasNamespace),
			"url":           llx.StringData(f.Url),
			"guardrailUuid": llx.StringData(f.GuardrailUuid),
			"createdAt":     llx.TimeDataPtr(gradientaiTime(f.CreatedAt)),
			"updatedAt":     llx.TimeDataPtr(gradientaiTime(f.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDigitaloceanGradientaiAgent) versions() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	versions, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]*godo.AgentVersion, *godo.Response, error) {
		return client.AgentPlatform.ListAgentVersions(c, r.Uuid.Data, o)
	})
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(versions))
	for _, v := range versions {
		if v == nil {
			continue
		}
		tags := make([]interface{}, len(v.Tags))
		for i, t := range v.Tags {
			tags[i] = t
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.gradientai.agent.version", map[string]*llx.RawData{
			"__id":             llx.StringData(r.Uuid.Data + "/" + v.ID),
			"id":               llx.StringData(v.ID),
			"agentUuid":        llx.StringData(v.AgentUuid),
			"name":             llx.StringData(v.Name),
			"description":      llx.StringData(v.Description),
			"instruction":      llx.StringData(v.Instruction),
			"modelName":        llx.StringData(v.ModelName),
			"versionHash":      llx.StringData(v.VersionHash),
			"currentlyApplied": llx.BoolData(v.CurrentlyApplied),
			"canRollback":      llx.BoolData(v.CanRollback),
			"createdByEmail":   llx.StringData(v.CreatedByEmail),
			"temperature":      llx.FloatData(v.Temperature),
			"topP":             llx.FloatData(v.TopP),
			"maxTokens":        llx.IntData(v.MaxTokens),
			"k":                llx.IntData(v.K),
			"provideCitations": llx.BoolData(v.ProvideCitations),
			"retrievalMethod":  llx.StringData(v.RetrievalMethod),
			"triggerAction":    llx.StringData(v.TriggerAction),
			"tags":             llx.ArrayData(tags, types.String),
			"createdAt":        llx.TimeDataPtr(gradientaiTime(v.CreatedAt)),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDigitaloceanGradientaiAgent) apiKeys() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	keys, err := paginate(context.Background(), func(c context.Context, o *godo.ListOptions) ([]*godo.ApiKeyInfo, *godo.Response, error) {
		return client.AgentPlatform.ListAgentAPIKeys(c, r.Uuid.Data, o)
	})
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(keys))
	for _, k := range keys {
		if k == nil {
			continue
		}
		// SecretKey is deliberately not surfaced.
		res, err := CreateResource(r.MqlRuntime, "digitalocean.gradientai.agent.apiKey", map[string]*llx.RawData{
			"__id":      llx.StringData(r.Uuid.Data + "/" + k.Uuid),
			"uuid":      llx.StringData(k.Uuid),
			"agentUuid": llx.StringData(r.Uuid.Data),
			"name":      llx.StringData(k.Name),
			"createdBy": llx.StringData(k.CreatedBy),
			"createdAt": llx.TimeDataPtr(gradientaiTime(k.CreatedAt)),
			"deletedAt": llx.TimeDataPtr(gradientaiTime(k.DeletedAt)),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// ----- Models -----

func (r *mqlDigitaloceanGradientai) models() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	models, err := paginate(context.Background(), client.AgentPlatform.ListAvailableModels)
	if err != nil {
		return nil, err
	}

	all := make([]interface{}, 0, len(models))
	for _, m := range models {
		res, err := newMqlGradientaiModel(r.MqlRuntime, m)
		if err != nil {
			return nil, err
		}
		if res != nil {
			all = append(all, res)
		}
	}
	return all, nil
}

func newMqlGradientaiModel(runtime *plugin.Runtime, m *godo.Model) (*mqlDigitaloceanGradientaiModel, error) {
	if m == nil {
		return nil, nil
	}

	capabilities := make([]interface{}, len(m.Capabilities))
	for i, c := range m.Capabilities {
		capabilities[i] = c
	}
	usecases := make([]interface{}, len(m.Usecases))
	for i, u := range m.Usecases {
		usecases[i] = u
	}

	modalities := map[string]interface{}{}
	if m.Modalities != nil {
		in := make([]interface{}, len(m.Modalities.Input))
		for i, v := range m.Modalities.Input {
			in[i] = v
		}
		out := make([]interface{}, len(m.Modalities.Output))
		for i, v := range m.Modalities.Output {
			out[i] = v
		}
		modalities = map[string]interface{}{"input": in, "output": out}
	}

	pricing := map[string]interface{}{}
	if p := m.Pricing; p != nil {
		pricing = map[string]interface{}{
			"inputPricePerMillion":      p.InputPricePerMillion,
			"outputPricePerMillion":     p.OutputPricePerMillion,
			"pricePerImage":             p.PricePerImage,
			"pricePerSecond":            p.PricePerSecond,
			"textInputPricePerMillion":  p.TextInputPricePerMillion,
			"textOutputPricePerMillion": p.TextOutputPricePerMillion,
		}
	}

	version := map[string]interface{}{}
	if v := m.Version; v != nil {
		version = map[string]interface{}{"major": int64(v.Major), "minor": int64(v.Minor), "patch": int64(v.Patch)}
	}

	agreementName, agreementURL := "", ""
	if m.Agreement != nil {
		agreementName = m.Agreement.Name
		agreementURL = m.Agreement.Url
	}

	res, err := CreateResource(runtime, "digitalocean.gradientai.model", map[string]*llx.RawData{
		"__id":              llx.StringData(m.Uuid),
		"uuid":              llx.StringData(m.Uuid),
		"name":              llx.StringData(m.Name),
		"provider":          llx.StringData(m.Provider),
		"type":              llx.StringData(m.Type),
		"isFoundational":    llx.BoolData(m.IsFoundational),
		"modelAvailability": llx.StringData(m.ModelAvailability),
		"inferenceName":     llx.StringData(m.InferenceName),
		"inferenceVersion":  llx.StringData(m.InferenceVersion),
		"uploadComplete":    llx.BoolData(m.UploadComplete),
		"url":               llx.StringData(m.Url),
		"contextWindow":     llx.StringData(m.ContextWindow),
		"parameterCount":    llx.FloatData(m.ParameterCount),
		"capabilities":      llx.ArrayData(capabilities, types.String),
		"usecases":          llx.ArrayData(usecases, types.String),
		"modalities":        llx.DictData(modalities),
		"pricing":           llx.DictData(pricing),
		"version":           llx.DictData(version),
		"agreementName":     llx.StringData(agreementName),
		"agreementUrl":      llx.StringData(agreementURL),
		"createdAt":         llx.TimeDataPtr(gradientaiTime(m.CreatedAt)),
		"updatedAt":         llx.TimeDataPtr(gradientaiTime(m.UpdatedAt)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDigitaloceanGradientaiModel), nil
}

// ----- Custom models -----

func (r *mqlDigitaloceanGradientai) customModels() ([]interface{}, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	client := conn.Client()

	var all []interface{}
	opt := &godo.CustomModelListOptions{ListOptions: godo.ListOptions{PerPage: 200}}
	for {
		resp, httpResp, err := client.AgentPlatform.ListCustomModels(context.Background(), opt)
		if err != nil {
			return nil, err
		}
		if resp != nil {
			for _, m := range resp.Models {
				if m == nil {
					continue
				}
				inputMods := make([]interface{}, len(m.InputModalities))
				for i, v := range m.InputModalities {
					inputMods[i] = v
				}
				outputMods := make([]interface{}, len(m.OutputModalities))
				for i, v := range m.OutputModalities {
					outputMods[i] = v
				}
				deployments := make([]interface{}, 0, len(m.ActiveDeployments))
				for _, d := range m.ActiveDeployments {
					if d == nil {
						continue
					}
					deployments = append(deployments, convert.ToValue(d))
				}
				var sourceRef map[string]interface{}
				if m.SourceRef != nil {
					// Surface the source location, but omit the Hugging Face
					// access token.
					sourceRef = map[string]interface{}{
						"repoId":     m.SourceRef.RepoId,
						"commitSha":  m.SourceRef.CommitSha,
						"accessType": string(m.SourceRef.AccessType),
						"bucket":     m.SourceRef.Bucket,
						"region":     m.SourceRef.Region,
						"prefix":     m.SourceRef.Prefix,
					}
				}
				res, err := CreateResource(r.MqlRuntime, "digitalocean.gradientai.customModel", map[string]*llx.RawData{
					"__id":                 llx.StringData(m.Uuid),
					"uuid":                 llx.StringData(m.Uuid),
					"name":                 llx.StringData(m.Name),
					"description":          llx.StringData(m.Description),
					"status":               llx.StringData(string(m.Status)),
					"errorMessage":         llx.StringData(m.ErrorMessage),
					"architecture":         llx.StringData(m.Architecture),
					"sourceType":           llx.StringData(string(m.SourceType)),
					"totalSizeBytes":       llx.StringData(m.TotalSizeBytes),
					"fileCount":            llx.IntData(int64(m.FileCount)),
					"license":              llx.StringData(m.License),
					"contextLength":        llx.IntData(int64(m.ContextLength)),
					"costEstimatePerMonth": llx.IntData(int64(m.CostEstimatePerMonth)),
					"inputModalities":      llx.ArrayData(inputMods, types.String),
					"outputModalities":     llx.ArrayData(outputMods, types.String),
					"parameters":           llx.StringData(m.Parameters),
					"teamId":               llx.StringData(m.TeamId),
					"storageRegion":        llx.StringData(m.StorageRegion),
					"sourceRef":            llx.DictData(sourceRef),
					"configJson":           llx.DictData(m.ConfigJson),
					"activeDeployments":    llx.ArrayData(deployments, types.Dict),
					"createdAt":            llx.TimeDataPtr(gradientaiTime(m.CreatedAt)),
					"updatedAt":            llx.TimeDataPtr(gradientaiTime(m.UpdatedAt)),
				})
				if err != nil {
					return nil, err
				}
				all = append(all, res)
			}
		}
		if httpResp == nil || httpResp.Links == nil || httpResp.Links.IsLastPage() {
			break
		}
		page, err := httpResp.Links.CurrentPage()
		if err != nil {
			return nil, err
		}
		opt.Page = page + 1
	}
	return all, nil
}
