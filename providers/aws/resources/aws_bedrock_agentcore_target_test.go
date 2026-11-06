// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	bacctypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"github.com/stretchr/testify/assert"
)

func TestGatewayTargetShapeOf(t *testing.T) {
	// Synthetic: one configuration per union member, as the SDK decodes them.
	t.Run("mcp server", func(t *testing.T) {
		s := gatewayTargetShapeOf(&bacctypes.TargetConfigurationMemberMcp{
			Value: &bacctypes.McpTargetConfigurationMemberMcpServer{
				Value: bacctypes.McpServerTargetConfiguration{Endpoint: aws.String("https://mcp.example.com/mcp")},
			},
		})
		assert.Equal(t, "mcp", s.configurationType)
		assert.Equal(t, "mcpServer", s.targetType)
		assert.Equal(t, "https://mcp.example.com/mcp", aws.ToString(s.endpoint))
		assert.Empty(t, s.lambdaArn)
	})

	t.Run("lambda", func(t *testing.T) {
		s := gatewayTargetShapeOf(&bacctypes.TargetConfigurationMemberMcp{
			Value: &bacctypes.McpTargetConfigurationMemberLambda{
				Value: bacctypes.McpLambdaTargetConfiguration{LambdaArn: aws.String("arn:aws:lambda:us-east-1:123456789012:function:tools")},
			},
		})
		assert.Equal(t, "lambda", s.targetType)
		assert.Equal(t, "arn:aws:lambda:us-east-1:123456789012:function:tools", s.lambdaArn)
		assert.Nil(t, s.endpoint)
	})

	t.Run("api gateway", func(t *testing.T) {
		s := gatewayTargetShapeOf(&bacctypes.TargetConfigurationMemberMcp{
			Value: &bacctypes.McpTargetConfigurationMemberApiGateway{
				Value: bacctypes.ApiGatewayTargetConfiguration{RestApiId: aws.String("a1b2c3"), Stage: aws.String("prod")},
			},
		})
		assert.Equal(t, "apiGateway", s.targetType)
		assert.Equal(t, "a1b2c3", s.restApiId)
		assert.Equal(t, "prod", aws.ToString(s.apiGatewayStage))
	})

	t.Run("openapi and smithy carry no backend reference", func(t *testing.T) {
		s := gatewayTargetShapeOf(&bacctypes.TargetConfigurationMemberMcp{
			Value: &bacctypes.McpTargetConfigurationMemberOpenApiSchema{Value: &bacctypes.ApiSchemaConfigurationMemberInlinePayload{Value: "{}"}},
		})
		assert.Equal(t, "openApiSchema", s.targetType)
		assert.Nil(t, s.endpoint)
		s = gatewayTargetShapeOf(&bacctypes.TargetConfigurationMemberMcp{
			Value: &bacctypes.McpTargetConfigurationMemberSmithyModel{Value: &bacctypes.ApiSchemaConfigurationMemberInlinePayload{Value: "{}"}},
		})
		assert.Equal(t, "smithyModel", s.targetType)
	})

	t.Run("http runtime and passthrough", func(t *testing.T) {
		s := gatewayTargetShapeOf(&bacctypes.TargetConfigurationMemberHttp{
			Value: &bacctypes.HttpTargetConfigurationMemberAgentcoreRuntime{
				Value: bacctypes.RuntimeTargetConfiguration{Arn: aws.String("arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt-1")},
			},
		})
		assert.Equal(t, "http", s.configurationType)
		assert.Equal(t, "agentcoreRuntime", s.targetType)
		assert.Equal(t, "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt-1", s.runtimeArn)

		s = gatewayTargetShapeOf(&bacctypes.TargetConfigurationMemberHttp{
			Value: &bacctypes.HttpTargetConfigurationMemberPassthrough{
				Value: bacctypes.PassthroughTargetConfiguration{Endpoint: aws.String("https://api.example.com")},
			},
		})
		assert.Equal(t, "passthrough", s.targetType)
		assert.Equal(t, "https://api.example.com", aws.ToString(s.endpoint))
	})

	t.Run("inference provider", func(t *testing.T) {
		s := gatewayTargetShapeOf(&bacctypes.TargetConfigurationMemberInference{
			Value: &bacctypes.InferenceTargetConfigurationMemberProvider{
				Value: bacctypes.InferenceProviderTargetConfiguration{Endpoint: aws.String("https://llm.example.com")},
			},
		})
		assert.Equal(t, "inference", s.configurationType)
		assert.Equal(t, "provider", s.targetType)
		assert.Equal(t, "https://llm.example.com", aws.ToString(s.endpoint))
	})

	t.Run("absent configuration", func(t *testing.T) {
		s := gatewayTargetShapeOf(nil)
		assert.Empty(t, s.configurationType)
		assert.Empty(t, s.targetType)
	})
}

func TestGatewayTargetPrivateEndpointOf(t *testing.T) {
	// Synthetic: managed VPC endpoint addressed by VPC ARN.
	pe := gatewayTargetPrivateEndpointOf(&bacctypes.PrivateEndpointMemberManagedVpcResource{
		Value: bacctypes.ManagedVpcResource{
			VpcIdentifier:    aws.String("arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0abc"),
			SubnetIds:        []string{"subnet-1", "subnet-2"},
			SecurityGroupIds: []string{"sg-1"},
		},
	})
	assert.Equal(t, "managedVpcResource", pe.kind)
	assert.Equal(t, "vpc-0abc", pe.vpcId)
	assert.Equal(t, []string{"subnet-1", "subnet-2"}, pe.subnetIds)
	assert.Equal(t, []string{"sg-1"}, pe.securityGroups)

	// Synthetic: VPC addressed by id.
	pe = gatewayTargetPrivateEndpointOf(&bacctypes.PrivateEndpointMemberManagedVpcResource{
		Value: bacctypes.ManagedVpcResource{VpcIdentifier: aws.String("vpc-0def")},
	})
	assert.Equal(t, "vpc-0def", pe.vpcId)

	pe = gatewayTargetPrivateEndpointOf(&bacctypes.PrivateEndpointMemberSelfManagedLatticeResource{})
	assert.Equal(t, "selfManagedLatticeResource", pe.kind)
	assert.Empty(t, pe.vpcId)

	pe = gatewayTargetPrivateEndpointOf(nil)
	assert.Empty(t, pe.kind)
}

func TestGatewayTargetCredentialsOf(t *testing.T) {
	// Synthetic: one OAuth and one API-key provider plus the gateway role.
	c := gatewayTargetCredentialsOf([]bacctypes.CredentialProviderConfiguration{
		{
			CredentialProviderType: bacctypes.CredentialProviderTypeOauth,
			CredentialProvider: &bacctypes.CredentialProviderMemberOauthCredentialProvider{
				Value: bacctypes.OAuthCredentialProvider{ProviderArn: aws.String("arn:oauth"), Scopes: []string{"repo", "read:org"}},
			},
		},
		{
			CredentialProviderType: bacctypes.CredentialProviderTypeApiKey,
			CredentialProvider: &bacctypes.CredentialProviderMemberApiKeyCredentialProvider{
				Value: bacctypes.GatewayApiKeyCredentialProvider{ProviderArn: aws.String("arn:apikey")},
			},
		},
		{CredentialProviderType: bacctypes.CredentialProviderTypeGatewayIamRole},
	})
	assert.Equal(t, []string{"OAUTH", "API_KEY", "GATEWAY_IAM_ROLE"}, c.types)
	assert.Equal(t, []string{"arn:oauth"}, c.oauthArns)
	assert.Equal(t, []string{"repo", "read:org"}, c.scopes)
	assert.Equal(t, []string{"arn:apikey"}, c.apiKeyArns)

	// Synthetic: no configurations yields empty lists, not nil.
	c = gatewayTargetCredentialsOf(nil)
	assert.Equal(t, []string{}, c.types)
	assert.Equal(t, []string{}, c.oauthArns)
}

func TestPickByArn(t *testing.T) {
	// Synthetic: strings stand in for resources, the ARN is the value itself.
	list := []any{"arn:a", "arn:b", "arn:c"}
	id := func(r any) string { return r.(string) }
	assert.Equal(t, []any{"arn:c", "arn:a"}, pickByArn(list, []string{"arn:c", "arn:missing", "arn:a", "arn:c"}, id))
	assert.Equal(t, []any{}, pickByArn(list, nil, id))
}
