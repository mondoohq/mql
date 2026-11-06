// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	bacctypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
)

// gatewayTargetShape is what a gateway target's configuration union says
// about the backend it reaches.
type gatewayTargetShape struct {
	configurationType string
	targetType        string
	endpoint          *string
	lambdaArn         string
	restApiId         string
	apiGatewayStage   *string
	runtimeArn        string
}

func gatewayTargetShapeOf(cfg bacctypes.TargetConfiguration) gatewayTargetShape {
	res := gatewayTargetShape{}
	switch c := cfg.(type) {
	case *bacctypes.TargetConfigurationMemberMcp:
		res.configurationType = "mcp"
		switch m := c.Value.(type) {
		case *bacctypes.McpTargetConfigurationMemberMcpServer:
			res.targetType = "mcpServer"
			res.endpoint = m.Value.Endpoint
		case *bacctypes.McpTargetConfigurationMemberLambda:
			res.targetType = "lambda"
			res.lambdaArn = convert.ToValue(m.Value.LambdaArn)
		case *bacctypes.McpTargetConfigurationMemberOpenApiSchema:
			res.targetType = "openApiSchema"
		case *bacctypes.McpTargetConfigurationMemberSmithyModel:
			res.targetType = "smithyModel"
		case *bacctypes.McpTargetConfigurationMemberApiGateway:
			res.targetType = "apiGateway"
			res.restApiId = convert.ToValue(m.Value.RestApiId)
			res.apiGatewayStage = m.Value.Stage
		case *bacctypes.McpTargetConfigurationMemberConnector:
			res.targetType = "connector"
		}
	case *bacctypes.TargetConfigurationMemberHttp:
		res.configurationType = "http"
		switch m := c.Value.(type) {
		case *bacctypes.HttpTargetConfigurationMemberAgentcoreRuntime:
			res.targetType = "agentcoreRuntime"
			res.runtimeArn = convert.ToValue(m.Value.Arn)
		case *bacctypes.HttpTargetConfigurationMemberConnector:
			res.targetType = "connector"
		case *bacctypes.HttpTargetConfigurationMemberPassthrough:
			res.targetType = "passthrough"
			res.endpoint = m.Value.Endpoint
		}
	case *bacctypes.TargetConfigurationMemberInference:
		res.configurationType = "inference"
		switch m := c.Value.(type) {
		case *bacctypes.InferenceTargetConfigurationMemberProvider:
			res.targetType = "provider"
			res.endpoint = m.Value.Endpoint
		case *bacctypes.InferenceTargetConfigurationMemberConnector:
			res.targetType = "connector"
		}
	}
	return res
}

// gatewayTargetPrivateEndpoint is the private connectivity a target uses.
type gatewayTargetPrivateEndpoint struct {
	kind           string
	vpcId          string
	subnetIds      []string
	securityGroups []string
}

func gatewayTargetPrivateEndpointOf(pe bacctypes.PrivateEndpoint) gatewayTargetPrivateEndpoint {
	switch v := pe.(type) {
	case *bacctypes.PrivateEndpointMemberManagedVpcResource:
		return gatewayTargetPrivateEndpoint{
			kind:           "managedVpcResource",
			vpcId:          vpcIdFromIdentifier(convert.ToValue(v.Value.VpcIdentifier)),
			subnetIds:      v.Value.SubnetIds,
			securityGroups: v.Value.SecurityGroupIds,
		}
	case *bacctypes.PrivateEndpointMemberSelfManagedLatticeResource:
		return gatewayTargetPrivateEndpoint{kind: "selfManagedLatticeResource"}
	}
	return gatewayTargetPrivateEndpoint{}
}

// vpcIdFromIdentifier accepts a VPC ID or an EC2 VPC ARN and returns the ID.
func vpcIdFromIdentifier(identifier string) string {
	if parsed, err := arn.Parse(identifier); err == nil {
		return strings.TrimPrefix(parsed.Resource, "vpc/")
	}
	return identifier
}

// gatewayTargetCredentials is what a target's credential provider
// configurations say about the credentials the gateway presents.
type gatewayTargetCredentials struct {
	types      []string
	oauthArns  []string
	scopes     []string
	apiKeyArns []string
}

func gatewayTargetCredentialsOf(configs []bacctypes.CredentialProviderConfiguration) gatewayTargetCredentials {
	res := gatewayTargetCredentials{types: []string{}, oauthArns: []string{}, scopes: []string{}, apiKeyArns: []string{}}
	for _, c := range configs {
		if c.CredentialProviderType != "" {
			res.types = append(res.types, string(c.CredentialProviderType))
		}
		switch v := c.CredentialProvider.(type) {
		case *bacctypes.CredentialProviderMemberOauthCredentialProvider:
			if p := convert.ToValue(v.Value.ProviderArn); p != "" {
				res.oauthArns = append(res.oauthArns, p)
			}
			res.scopes = append(res.scopes, v.Value.Scopes...)
		case *bacctypes.CredentialProviderMemberApiKeyCredentialProvider:
			if p := convert.ToValue(v.Value.ProviderArn); p != "" {
				res.apiKeyArns = append(res.apiKeyArns, p)
			}
		}
	}
	return res
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) shape() (*gatewayTargetShape, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil {
		return nil, err
	}
	s := gatewayTargetShapeOf(detail.TargetConfiguration)
	return &s, nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) protocolType() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.ProtocolType == "" {
		a.ProtocolType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(detail.ProtocolType), nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) statusReasons() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		a.StatusReasons.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return stringsToArrayData(detail.StatusReasons), nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) lastSynchronizedAt() (*time.Time, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.LastSynchronizedAt == nil {
		a.LastSynchronizedAt.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return detail.LastSynchronizedAt, nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) configurationType() (string, error) {
	s, err := a.shape()
	if err != nil {
		return "", err
	}
	if s == nil || s.configurationType == "" {
		a.ConfigurationType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return s.configurationType, nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) targetType() (string, error) {
	s, err := a.shape()
	if err != nil {
		return "", err
	}
	if s == nil || s.targetType == "" {
		a.TargetType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return s.targetType, nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) endpoint() (string, error) {
	s, err := a.shape()
	if err != nil {
		return "", err
	}
	if s == nil || convert.ToValue(s.endpoint) == "" {
		a.Endpoint.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *s.endpoint, nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) lambdaFunction() (*mqlAwsLambdaFunction, error) {
	s, err := a.shape()
	if err != nil {
		return nil, err
	}
	if s == nil || s.lambdaArn == "" {
		a.LambdaFunction.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsLambdaFunction, map[string]*llx.RawData{"arn": llx.StringData(s.lambdaArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsLambdaFunction), nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) apiGateway() (*mqlAwsApigatewayRestapi, error) {
	s, err := a.shape()
	if err != nil {
		return nil, err
	}
	if s == nil || s.restApiId == "" {
		a.ApiGateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	restApiArn := fmt.Sprintf(apiArnPattern, a.Region.Data, conn.AccountId(), s.restApiId)
	res, err := NewResource(a.MqlRuntime, ResourceAwsApigatewayRestapi, map[string]*llx.RawData{"arn": llx.StringData(restApiArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsApigatewayRestapi), nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) apiGatewayStage() (string, error) {
	s, err := a.shape()
	if err != nil {
		return "", err
	}
	if s == nil || convert.ToValue(s.apiGatewayStage) == "" {
		a.ApiGatewayStage.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *s.apiGatewayStage, nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) agentRuntime() (*mqlAwsBedrockAgentCoreRuntime, error) {
	s, err := a.shape()
	if err != nil {
		return nil, err
	}
	if s == nil || s.runtimeArn == "" {
		a.AgentRuntime.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	agentCore, err := agentCoreRoot(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	runtimes := agentCore.GetRuntimes()
	if runtimes.Error != nil {
		return nil, runtimes.Error
	}
	for _, raw := range runtimes.Data {
		if rt, ok := raw.(*mqlAwsBedrockAgentCoreRuntime); ok && rt.Arn.Data == s.runtimeArn {
			return rt, nil
		}
	}
	a.AgentRuntime.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) privateEndpoint() (*gatewayTargetPrivateEndpoint, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil {
		return nil, err
	}
	pe := gatewayTargetPrivateEndpointOf(detail.PrivateEndpoint)
	return &pe, nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) privateEndpointType() (string, error) {
	pe, err := a.privateEndpoint()
	if err != nil {
		return "", err
	}
	if pe == nil || pe.kind == "" {
		a.PrivateEndpointType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return pe.kind, nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) privateEndpointVpc() (*mqlAwsVpc, error) {
	pe, err := a.privateEndpoint()
	if err != nil {
		return nil, err
	}
	if pe == nil || pe.vpcId == "" {
		a.PrivateEndpointVpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsVpc, map[string]*llx.RawData{
		"id":     llx.StringData(pe.vpcId),
		"region": llx.StringData(a.Region.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) privateEndpointSubnets() ([]any, error) {
	pe, err := a.privateEndpoint()
	if err != nil {
		return nil, err
	}
	if pe == nil {
		return []any{}, nil
	}
	return agentCoreSubnets(a.MqlRuntime, a.Region.Data, &bacctypes.VpcConfig{Subnets: pe.subnetIds})
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) privateEndpointSecurityGroups() ([]any, error) {
	pe, err := a.privateEndpoint()
	if err != nil {
		return nil, err
	}
	if pe == nil {
		return []any{}, nil
	}
	return agentCoreSecurityGroups(a.MqlRuntime, a.Region.Data, &bacctypes.VpcConfig{SecurityGroups: pe.securityGroups})
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) credentials() (*gatewayTargetCredentials, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil {
		return nil, err
	}
	c := gatewayTargetCredentialsOf(detail.CredentialProviderConfigurations)
	return &c, nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) credentialProviderTypes() ([]any, error) {
	c, err := a.credentials()
	if err != nil {
		return nil, err
	}
	if c == nil {
		a.CredentialProviderTypes.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return stringsToArrayData(c.types), nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) oauthScopes() ([]any, error) {
	c, err := a.credentials()
	if err != nil {
		return nil, err
	}
	if c == nil {
		a.OauthScopes.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return stringsToArrayData(c.scopes), nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) oauth2CredentialProviders() ([]any, error) {
	c, err := a.credentials()
	if err != nil {
		return nil, err
	}
	if c == nil || len(c.oauthArns) == 0 {
		return []any{}, nil
	}
	agentCore, err := agentCoreRoot(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	providers := agentCore.GetOauth2CredentialProviders()
	if providers.Error != nil {
		return nil, providers.Error
	}
	return pickByArn(providers.Data, c.oauthArns, func(r any) string {
		if p, ok := r.(*mqlAwsBedrockAgentCoreOauth2CredentialProvider); ok {
			return p.Arn.Data
		}
		return ""
	}), nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) apiKeyCredentialProviders() ([]any, error) {
	c, err := a.credentials()
	if err != nil {
		return nil, err
	}
	if c == nil || len(c.apiKeyArns) == 0 {
		return []any{}, nil
	}
	agentCore, err := agentCoreRoot(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	providers := agentCore.GetApiKeyCredentialProviders()
	if providers.Error != nil {
		return nil, providers.Error
	}
	return pickByArn(providers.Data, c.apiKeyArns, func(r any) string {
		if p, ok := r.(*mqlAwsBedrockAgentCoreApiKeyCredentialProvider); ok {
			return p.Arn.Data
		}
		return ""
	}), nil
}

// pickByArn returns the resources in list whose ARN is one of want, in the
// order of want. ARNs with no matching resource are left out.
func pickByArn(list []any, want []string, arnOf func(any) string) []any {
	byArn := make(map[string]any, len(list))
	for _, r := range list {
		if a := arnOf(r); a != "" {
			byArn[a] = r
		}
	}
	res := []any{}
	seen := map[string]bool{}
	for _, w := range want {
		if r, ok := byArn[w]; ok && !seen[w] {
			res = append(res, r)
			seen[w] = true
		}
	}
	return res
}
