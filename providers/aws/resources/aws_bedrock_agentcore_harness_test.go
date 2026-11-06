// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	bacctypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestHarnessModelOf(t *testing.T) {
	// Synthetic: one model configuration per union member.
	m := harnessModelOf(&bacctypes.HarnessModelConfigurationMemberBedrockModelConfig{
		Value: bacctypes.HarnessBedrockModelConfig{ModelId: aws.String("anthropic.claude-sonnet")},
	})
	assert.Equal(t, "bedrock", m.provider)
	assert.Equal(t, "anthropic.claude-sonnet", aws.ToString(m.modelId))
	assert.Nil(t, m.apiBase)
	assert.Empty(t, m.apiKeyArn)

	m = harnessModelOf(&bacctypes.HarnessModelConfigurationMemberOpenAiModelConfig{
		Value: bacctypes.HarnessOpenAiModelConfig{
			ModelId:   aws.String("gpt-x"),
			ApiBase:   aws.String("https://llm.example.com/v1"),
			ApiKeyArn: aws.String("arn:apikey:openai"),
		},
	})
	assert.Equal(t, "openAi", m.provider)
	assert.Equal(t, "https://llm.example.com/v1", aws.ToString(m.apiBase))
	assert.Equal(t, "arn:apikey:openai", m.apiKeyArn)

	m = harnessModelOf(&bacctypes.HarnessModelConfigurationMemberGeminiModelConfig{
		Value: bacctypes.HarnessGeminiModelConfig{ModelId: aws.String("gemini-x"), ApiKeyArn: aws.String("arn:apikey:gemini")},
	})
	assert.Equal(t, "gemini", m.provider)
	assert.Nil(t, m.apiBase)
	assert.Equal(t, "arn:apikey:gemini", m.apiKeyArn)

	m = harnessModelOf(&bacctypes.HarnessModelConfigurationMemberLiteLlmModelConfig{
		Value: bacctypes.HarnessLiteLlmModelConfig{ModelId: aws.String("x"), ApiBase: aws.String("http://litellm:4000")},
	})
	assert.Equal(t, "liteLlm", m.provider)
	assert.Equal(t, "http://litellm:4000", aws.ToString(m.apiBase))
	assert.Empty(t, m.apiKeyArn)

	assert.Empty(t, harnessModelOf(nil).provider)
}

func TestHarnessToolsOf(t *testing.T) {
	// Synthetic: a gateway, a remote MCP server with a credential header, and a browser.
	tools := harnessToolsOf([]bacctypes.HarnessTool{
		{
			Type:   bacctypes.HarnessToolTypeAgentcoreGateway,
			Config: &bacctypes.HarnessToolConfigurationMemberAgentCoreGateway{Value: bacctypes.HarnessAgentCoreGatewayConfig{GatewayArn: aws.String("arn:gw")}},
		},
		{
			Type: bacctypes.HarnessToolTypeRemoteMcp,
			Config: &bacctypes.HarnessToolConfigurationMemberRemoteMcp{Value: bacctypes.HarnessRemoteMcpConfig{
				Url:     aws.String("https://mcp.example.com"),
				Headers: map[string]string{"Authorization": "Bearer secret-token"},
			}},
		},
		{Type: bacctypes.HarnessToolTypeAgentcoreBrowser},
	})
	assert.Equal(t, []string{"agentcore_gateway", "remote_mcp", "agentcore_browser"}, tools.types)
	assert.Equal(t, []string{"arn:gw"}, tools.gatewayArns)
	assert.Equal(t, []string{"https://mcp.example.com"}, tools.mcpUrls)
	assert.NotContains(t, tools.mcpUrls, "Bearer secret-token")

	empty := harnessToolsOf(nil)
	assert.Equal(t, []string{}, empty.types)
	assert.Equal(t, []string{}, empty.gatewayArns)
}

func TestHarnessMemoryOf(t *testing.T) {
	// Synthetic: one memory configuration per union member.
	kind, arn := harnessMemoryOf(&bacctypes.HarnessMemoryConfigurationMemberAgentCoreMemoryConfiguration{
		Value: bacctypes.HarnessAgentCoreMemoryConfiguration{Arn: aws.String("arn:memory:1")},
	})
	assert.Equal(t, "agentCoreMemory", kind)
	assert.Equal(t, "arn:memory:1", arn)

	kind, arn = harnessMemoryOf(&bacctypes.HarnessMemoryConfigurationMemberManagedMemoryConfiguration{
		Value: bacctypes.HarnessManagedMemoryConfiguration{Arn: aws.String("arn:memory:managed")},
	})
	assert.Equal(t, "managedMemory", kind)
	assert.Equal(t, "arn:memory:managed", arn)

	kind, arn = harnessMemoryOf(&bacctypes.HarnessMemoryConfigurationMemberDisabled{})
	assert.Equal(t, "disabled", kind)
	assert.Empty(t, arn)

	kind, _ = harnessMemoryOf(nil)
	assert.Empty(t, kind)
}

func TestHarnessRuntimeEnvironment(t *testing.T) {
	// Synthetic: VPC runtime environment.
	env := harnessRuntimeEnvironment(&bacctypes.HarnessEnvironmentProviderMemberAgentCoreRuntimeEnvironment{
		Value: bacctypes.HarnessAgentCoreRuntimeEnvironment{
			AgentRuntimeArn: aws.String("arn:runtime"),
			NetworkConfiguration: &bacctypes.NetworkConfiguration{
				NetworkMode:       bacctypes.NetworkModeVpc,
				NetworkModeConfig: &bacctypes.VpcConfig{Subnets: []string{"subnet-1"}},
			},
		},
	})
	require.NotNil(t, env)
	assert.Equal(t, "arn:runtime", aws.ToString(env.AgentRuntimeArn))

	assert.Nil(t, harnessRuntimeEnvironment(nil))
}

func TestHarnessInt(t *testing.T) {
	// Synthetic: an unset limit is null, not zero.
	var field plugin.TValue[int64]
	v, err := harnessInt(nil, &field)
	require.NoError(t, err)
	assert.Zero(t, v)
	assert.True(t, field.IsNull())

	field = plugin.TValue[int64]{}
	v, err = harnessInt(aws.Int32(25), &field)
	require.NoError(t, err)
	assert.Equal(t, int64(25), v)
	assert.False(t, field.IsNull())
}
