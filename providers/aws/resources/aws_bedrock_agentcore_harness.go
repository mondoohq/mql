// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	bacctypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
)

type mqlAwsBedrockAgentCoreHarnessInternal struct {
	cacheRegion string
	fetchLock   sync.Mutex
	fetched     atomic.Bool
	detail      *bacctypes.Harness
}

func (a *mqlAwsBedrockAgentCore) harnesses() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.collectJobs(a.agentCoreRegionTasks(conn, func(ctx context.Context, region string) ([]any, error) {
		svc := conn.BedrockAgentCoreControl(region)
		res := []any{}
		paginator := bedrockagentcorecontrol.NewListHarnessesPaginator(svc, &bedrockagentcorecontrol.ListHarnessesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, h := range page.Harnesses {
				mqlH, err := CreateResource(a.MqlRuntime, ResourceAwsBedrockAgentCoreHarness, map[string]*llx.RawData{
					"__id":      llx.StringDataPtr(h.Arn),
					"arn":       llx.StringDataPtr(h.Arn),
					"id":        llx.StringDataPtr(h.HarnessId),
					"name":      llx.StringDataPtr(h.HarnessName),
					"region":    llx.StringData(region),
					"status":    llx.StringData(string(h.Status)),
					"version":   llx.StringDataPtr(h.HarnessVersion),
					"createdAt": llx.TimeDataPtr(h.CreatedAt),
					"updatedAt": llx.TimeDataPtr(h.UpdatedAt),
				})
				if err != nil {
					return nil, err
				}
				cast := mqlH.(*mqlAwsBedrockAgentCoreHarness)
				cast.cacheRegion = region
				res = append(res, cast)
			}
		}
		return res, nil
	}))
}

func (a *mqlAwsBedrockAgentCoreHarness) fetchDetail() (*bacctypes.Harness, error) {
	if a.fetched.Load() {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched.Load() {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(a.cacheRegion)
	harnessId := a.Id.Data
	out, err := svc.GetHarness(context.Background(), &bedrockagentcorecontrol.GetHarnessInput{HarnessId: &harnessId})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, llx.Forbidden(err, llx.WithPermissions("bedrock-agentcore:GetHarness"))
		}
		return nil, err
	}
	a.detail = out.Harness
	a.fetched.Store(true)
	return a.detail, nil
}

// harnessModel is what a harness's model configuration union says about the
// model it calls.
type harnessModel struct {
	provider  string
	modelId   *string
	apiBase   *string
	apiKeyArn string
}

func harnessModelOf(cfg bacctypes.HarnessModelConfiguration) harnessModel {
	switch v := cfg.(type) {
	case *bacctypes.HarnessModelConfigurationMemberBedrockModelConfig:
		return harnessModel{provider: "bedrock", modelId: v.Value.ModelId}
	case *bacctypes.HarnessModelConfigurationMemberOpenAiModelConfig:
		return harnessModel{provider: "openAi", modelId: v.Value.ModelId, apiBase: v.Value.ApiBase, apiKeyArn: convert.ToValue(v.Value.ApiKeyArn)}
	case *bacctypes.HarnessModelConfigurationMemberGeminiModelConfig:
		return harnessModel{provider: "gemini", modelId: v.Value.ModelId, apiKeyArn: convert.ToValue(v.Value.ApiKeyArn)}
	case *bacctypes.HarnessModelConfigurationMemberLiteLlmModelConfig:
		return harnessModel{provider: "liteLlm", modelId: v.Value.ModelId, apiBase: v.Value.ApiBase, apiKeyArn: convert.ToValue(v.Value.ApiKeyArn)}
	}
	return harnessModel{}
}

// harnessTools is what a harness's tool list says about the tools it calls.
// Remote MCP headers are never read: they can carry credentials.
type harnessTools struct {
	types       []string
	gatewayArns []string
	mcpUrls     []string
}

func harnessToolsOf(tools []bacctypes.HarnessTool) harnessTools {
	res := harnessTools{types: []string{}, gatewayArns: []string{}, mcpUrls: []string{}}
	for _, t := range tools {
		if t.Type != "" {
			res.types = append(res.types, string(t.Type))
		}
		switch c := t.Config.(type) {
		case *bacctypes.HarnessToolConfigurationMemberAgentCoreGateway:
			if arn := convert.ToValue(c.Value.GatewayArn); arn != "" {
				res.gatewayArns = append(res.gatewayArns, arn)
			}
		case *bacctypes.HarnessToolConfigurationMemberRemoteMcp:
			if u := convert.ToValue(c.Value.Url); u != "" {
				res.mcpUrls = append(res.mcpUrls, u)
			}
		}
	}
	return res
}

// harnessRuntimeEnvironment returns the AgentCore runtime environment the
// harness runs in, or nil when none is reported.
func harnessRuntimeEnvironment(env bacctypes.HarnessEnvironmentProvider) *bacctypes.HarnessAgentCoreRuntimeEnvironment {
	if v, ok := env.(*bacctypes.HarnessEnvironmentProviderMemberAgentCoreRuntimeEnvironment); ok {
		return &v.Value
	}
	return nil
}

// harnessMemoryOf reports the kind of memory a harness keeps and the ARN of
// its memory store, if any.
func harnessMemoryOf(cfg bacctypes.HarnessMemoryConfiguration) (kind string, memoryArn string) {
	switch v := cfg.(type) {
	case *bacctypes.HarnessMemoryConfigurationMemberAgentCoreMemoryConfiguration:
		return "agentCoreMemory", convert.ToValue(v.Value.Arn)
	case *bacctypes.HarnessMemoryConfigurationMemberManagedMemoryConfiguration:
		return "managedMemory", convert.ToValue(v.Value.Arn)
	case *bacctypes.HarnessMemoryConfigurationMemberDisabled:
		return "disabled", ""
	}
	return "", ""
}

func (a *mqlAwsBedrockAgentCoreHarness) failureReason() (string, error) {
	h, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if h == nil || convert.ToValue(h.FailureReason) == "" {
		a.FailureReason.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *h.FailureReason, nil
}

func (a *mqlAwsBedrockAgentCoreHarness) iamRole() (*mqlAwsIamRole, error) {
	h, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if h == nil {
		a.IamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return agentCoreRole(a.MqlRuntime, h.ExecutionRoleArn, &a.IamRole)
}

func (a *mqlAwsBedrockAgentCoreHarness) jwtAuthorizer() (*bacctypes.CustomJWTAuthorizerConfiguration, error) {
	h, err := a.fetchDetail()
	if err != nil || h == nil {
		return nil, err
	}
	return agentCoreJWTAuthorizer(h.AuthorizerConfiguration), nil
}

func (a *mqlAwsBedrockAgentCoreHarness) authorizerType() (string, error) {
	jwt, err := a.jwtAuthorizer()
	if err != nil {
		return "", err
	}
	if jwt == nil {
		a.AuthorizerType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return "CUSTOM_JWT", nil
}

func (a *mqlAwsBedrockAgentCoreHarness) authorizerDiscoveryUrl() (string, error) {
	jwt, err := a.jwtAuthorizer()
	if err != nil {
		return "", err
	}
	return jwtDiscoveryUrl(jwt, &a.AuthorizerDiscoveryUrl)
}

func (a *mqlAwsBedrockAgentCoreHarness) allowedClients() ([]any, error) {
	jwt, err := a.jwtAuthorizer()
	if err != nil {
		return nil, err
	}
	return jwtAuthorizerList(jwt, func(c *bacctypes.CustomJWTAuthorizerConfiguration) []string { return c.AllowedClients }, &a.AllowedClients)
}

func (a *mqlAwsBedrockAgentCoreHarness) allowedAudiences() ([]any, error) {
	jwt, err := a.jwtAuthorizer()
	if err != nil {
		return nil, err
	}
	return jwtAuthorizerList(jwt, func(c *bacctypes.CustomJWTAuthorizerConfiguration) []string { return c.AllowedAudience }, &a.AllowedAudiences)
}

func (a *mqlAwsBedrockAgentCoreHarness) allowedScopes() ([]any, error) {
	jwt, err := a.jwtAuthorizer()
	if err != nil {
		return nil, err
	}
	return jwtAuthorizerList(jwt, func(c *bacctypes.CustomJWTAuthorizerConfiguration) []string { return c.AllowedScopes }, &a.AllowedScopes)
}

func (a *mqlAwsBedrockAgentCoreHarness) model() (*harnessModel, error) {
	h, err := a.fetchDetail()
	if err != nil || h == nil {
		return nil, err
	}
	m := harnessModelOf(h.Model)
	return &m, nil
}

func (a *mqlAwsBedrockAgentCoreHarness) modelProvider() (string, error) {
	m, err := a.model()
	if err != nil {
		return "", err
	}
	if m == nil || m.provider == "" {
		a.ModelProvider.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return m.provider, nil
}

func (a *mqlAwsBedrockAgentCoreHarness) modelId() (string, error) {
	m, err := a.model()
	if err != nil {
		return "", err
	}
	if m == nil || convert.ToValue(m.modelId) == "" {
		a.ModelId.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *m.modelId, nil
}

func (a *mqlAwsBedrockAgentCoreHarness) modelApiBase() (string, error) {
	m, err := a.model()
	if err != nil {
		return "", err
	}
	if m == nil || convert.ToValue(m.apiBase) == "" {
		a.ModelApiBase.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *m.apiBase, nil
}

func (a *mqlAwsBedrockAgentCoreHarness) apiKeyCredentialProvider() (*mqlAwsBedrockAgentCoreApiKeyCredentialProvider, error) {
	m, err := a.model()
	if err != nil {
		return nil, err
	}
	if m == nil || m.apiKeyArn == "" {
		a.ApiKeyCredentialProvider.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	agentCore, err := harnessAgentCoreRoot(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	providers := agentCore.GetApiKeyCredentialProviders()
	if providers.Error != nil {
		return nil, providers.Error
	}
	for _, raw := range providers.Data {
		if p, ok := raw.(*mqlAwsBedrockAgentCoreApiKeyCredentialProvider); ok && p.Arn.Data == m.apiKeyArn {
			return p, nil
		}
	}
	a.ApiKeyCredentialProvider.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAwsBedrockAgentCoreHarness) tools() (*harnessTools, error) {
	h, err := a.fetchDetail()
	if err != nil || h == nil {
		return nil, err
	}
	t := harnessToolsOf(h.Tools)
	return &t, nil
}

func (a *mqlAwsBedrockAgentCoreHarness) toolTypes() ([]any, error) {
	t, err := a.tools()
	if err != nil {
		return nil, err
	}
	if t == nil {
		a.ToolTypes.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return stringsToArrayData(t.types), nil
}

func (a *mqlAwsBedrockAgentCoreHarness) allowedTools() ([]any, error) {
	h, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if h == nil {
		a.AllowedTools.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return stringsToArrayData(h.AllowedTools), nil
}

func (a *mqlAwsBedrockAgentCoreHarness) remoteMcpServerUrls() ([]any, error) {
	t, err := a.tools()
	if err != nil {
		return nil, err
	}
	if t == nil {
		a.RemoteMcpServerUrls.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return stringsToArrayData(t.mcpUrls), nil
}

func (a *mqlAwsBedrockAgentCoreHarness) gateways() ([]any, error) {
	t, err := a.tools()
	if err != nil {
		return nil, err
	}
	if t == nil || len(t.gatewayArns) == 0 {
		return []any{}, nil
	}
	agentCore, err := harnessAgentCoreRoot(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	gws := agentCore.GetGateways()
	if gws.Error != nil {
		return nil, gws.Error
	}
	want := map[string]bool{}
	for _, arn := range t.gatewayArns {
		want[arn] = true
	}
	res := []any{}
	for _, raw := range gws.Data {
		gw, ok := raw.(*mqlAwsBedrockAgentCoreGateway)
		if !ok {
			continue
		}
		gwArn := gw.GetArn()
		if gwArn.Error != nil {
			return nil, gwArn.Error
		}
		if want[gwArn.Data] {
			res = append(res, gw)
		}
	}
	return res, nil
}

func (a *mqlAwsBedrockAgentCoreHarness) runtimeEnvironment() (*bacctypes.HarnessAgentCoreRuntimeEnvironment, error) {
	h, err := a.fetchDetail()
	if err != nil || h == nil {
		return nil, err
	}
	return harnessRuntimeEnvironment(h.Environment), nil
}

func (a *mqlAwsBedrockAgentCoreHarness) agentRuntime() (*mqlAwsBedrockAgentCoreRuntime, error) {
	env, err := a.runtimeEnvironment()
	if err != nil {
		return nil, err
	}
	if env == nil || convert.ToValue(env.AgentRuntimeArn) == "" {
		a.AgentRuntime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	agentCore, err := harnessAgentCoreRoot(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	runtimes := agentCore.GetRuntimes()
	if runtimes.Error != nil {
		return nil, runtimes.Error
	}
	for _, raw := range runtimes.Data {
		if rt, ok := raw.(*mqlAwsBedrockAgentCoreRuntime); ok && rt.Arn.Data == *env.AgentRuntimeArn {
			return rt, nil
		}
	}
	a.AgentRuntime.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAwsBedrockAgentCoreHarness) networkMode() (string, error) {
	env, err := a.runtimeEnvironment()
	if err != nil {
		return "", err
	}
	if env == nil || env.NetworkConfiguration == nil || env.NetworkConfiguration.NetworkMode == "" {
		a.NetworkMode.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(env.NetworkConfiguration.NetworkMode), nil
}

func (a *mqlAwsBedrockAgentCoreHarness) vpcConfig() (*bacctypes.VpcConfig, error) {
	env, err := a.runtimeEnvironment()
	if err != nil || env == nil || env.NetworkConfiguration == nil {
		return nil, err
	}
	return env.NetworkConfiguration.NetworkModeConfig, nil
}

func (a *mqlAwsBedrockAgentCoreHarness) subnets() ([]any, error) {
	vpc, err := a.vpcConfig()
	if err != nil {
		return nil, err
	}
	return agentCoreSubnets(a.MqlRuntime, a.Region.Data, vpc)
}

func (a *mqlAwsBedrockAgentCoreHarness) securityGroups() ([]any, error) {
	vpc, err := a.vpcConfig()
	if err != nil {
		return nil, err
	}
	return agentCoreSecurityGroups(a.MqlRuntime, a.Region.Data, vpc)
}

func (a *mqlAwsBedrockAgentCoreHarness) memoryType() (string, error) {
	h, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	kind := ""
	if h != nil {
		kind, _ = harnessMemoryOf(h.Memory)
	}
	if kind == "" {
		a.MemoryType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return kind, nil
}

func (a *mqlAwsBedrockAgentCoreHarness) memory() (*mqlAwsBedrockAgentCoreMemory, error) {
	h, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	memoryArn := ""
	if h != nil {
		_, memoryArn = harnessMemoryOf(h.Memory)
	}
	if memoryArn == "" {
		a.Memory.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	agentCore, err := harnessAgentCoreRoot(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	memories := agentCore.GetMemories()
	if memories.Error != nil {
		return nil, memories.Error
	}
	for _, raw := range memories.Data {
		if m, ok := raw.(*mqlAwsBedrockAgentCoreMemory); ok && m.Arn.Data == memoryArn {
			return m, nil
		}
	}
	a.Memory.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAwsBedrockAgentCoreHarness) environmentVariableNames() ([]any, error) {
	h, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if h == nil {
		a.EnvironmentVariableNames.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return agentRuntimeEnvironmentVariableNames(h.EnvironmentVariables), nil
}

func harnessInt(v *int32, field *plugin.TValue[int64]) (int64, error) {
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*v), nil
}

func (a *mqlAwsBedrockAgentCoreHarness) maxIterations() (int64, error) {
	h, err := a.fetchDetail()
	if err != nil || h == nil {
		if err == nil {
			a.MaxIterations.State = plugin.StateIsSet | plugin.StateIsNull
		}
		return 0, err
	}
	return harnessInt(h.MaxIterations, &a.MaxIterations)
}

func (a *mqlAwsBedrockAgentCoreHarness) maxTokens() (int64, error) {
	h, err := a.fetchDetail()
	if err != nil || h == nil {
		if err == nil {
			a.MaxTokens.State = plugin.StateIsSet | plugin.StateIsNull
		}
		return 0, err
	}
	return harnessInt(h.MaxTokens, &a.MaxTokens)
}

func (a *mqlAwsBedrockAgentCoreHarness) timeoutSeconds() (int64, error) {
	h, err := a.fetchDetail()
	if err != nil || h == nil {
		if err == nil {
			a.TimeoutSeconds.State = plugin.StateIsSet | plugin.StateIsNull
		}
		return 0, err
	}
	return harnessInt(h.TimeoutSeconds, &a.TimeoutSeconds)
}

func (a *mqlAwsBedrockAgentCoreHarness) endpoints() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(a.cacheRegion)
	harnessId := a.Id.Data
	res := []any{}
	paginator := bedrockagentcorecontrol.NewListHarnessEndpointsPaginator(svc, &bedrockagentcorecontrol.ListHarnessEndpointsInput{
		HarnessId: &harnessId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if Is400AccessDeniedError(err) {
				if !plugin.StructuredErrors() {
					return res, nil
				}
				return nil, llx.Forbidden(err, llx.WithPermissions("bedrock-agentcore:ListHarnessEndpoints"))
			}
			return nil, err
		}
		for _, ep := range page.Endpoints {
			mqlEp, err := CreateResource(a.MqlRuntime, ResourceAwsBedrockAgentCoreHarnessEndpoint, map[string]*llx.RawData{
				"__id":          llx.StringDataPtr(ep.Arn),
				"arn":           llx.StringDataPtr(ep.Arn),
				"name":          llx.StringDataPtr(ep.EndpointName),
				"status":        llx.StringData(string(ep.Status)),
				"description":   llx.StringDataPtr(ep.Description),
				"liveVersion":   llx.StringDataPtr(ep.LiveVersion),
				"targetVersion": llx.StringDataPtr(ep.TargetVersion),
				"failureReason": llx.StringDataPtr(ep.FailureReason),
				"createdAt":     llx.TimeDataPtr(ep.CreatedAt),
				"updatedAt":     llx.TimeDataPtr(ep.UpdatedAt),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlEp)
		}
	}
	return res, nil
}

// harnessAgentCoreRoot returns the cached aws.bedrock.agentCore resource,
// whose lists resolve the harness's references to other AgentCore resources.
func harnessAgentCoreRoot(runtime *plugin.Runtime) (*mqlAwsBedrockAgentCore, error) {
	obj, err := CreateResource(runtime, ResourceAwsBedrockAgentCore, map[string]*llx.RawData{
		"__id": llx.StringData("aws.bedrock.agentCore"),
	})
	if err != nil {
		return nil, err
	}
	return obj.(*mqlAwsBedrockAgentCore), nil
}
