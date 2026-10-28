// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	bacctypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// --- Shared helpers ---

// agentCoreJWTAuthorizer returns the custom JWT authorizer from an AgentCore
// authorizer configuration, or nil when none is configured. A runtime with no
// authorizer configuration authenticates callers with IAM SigV4.
func agentCoreJWTAuthorizer(cfg bacctypes.AuthorizerConfiguration) *bacctypes.CustomJWTAuthorizerConfiguration {
	if v, ok := cfg.(*bacctypes.AuthorizerConfigurationMemberCustomJWTAuthorizer); ok {
		return &v.Value
	}
	return nil
}

// agentCoreRequestHeaderAllowlist returns the request headers an agent runtime
// passes through to the agent code. Empty when none are configured.
func agentCoreRequestHeaderAllowlist(cfg bacctypes.RequestHeaderConfiguration) []string {
	if v, ok := cfg.(*bacctypes.RequestHeaderConfigurationMemberRequestHeaderAllowlist); ok {
		return v.Value
	}
	return nil
}

// agentCoreRecordingLocation returns the bucket and key prefix browser
// session recordings are written to. Both are empty when no location is set.
func agentCoreRecordingLocation(rec *bacctypes.RecordingConfig) (bucket string, prefix string) {
	if rec == nil || rec.S3Location == nil {
		return "", ""
	}
	return convert.ToValue(rec.S3Location.Bucket), convert.ToValue(rec.S3Location.Prefix)
}

// agentCoreInterceptor is a gateway interceptor flattened out of the SDK union.
type agentCoreInterceptor struct {
	interceptionPoints []string
	passRequestHeaders bool
	lambdaArn          string
}

func agentCoreInterceptors(configs []bacctypes.GatewayInterceptorConfiguration) []agentCoreInterceptor {
	res := make([]agentCoreInterceptor, 0, len(configs))
	for _, cfg := range configs {
		ic := agentCoreInterceptor{interceptionPoints: make([]string, 0, len(cfg.InterceptionPoints))}
		for _, p := range cfg.InterceptionPoints {
			ic.interceptionPoints = append(ic.interceptionPoints, string(p))
		}
		if cfg.InputConfiguration != nil {
			ic.passRequestHeaders = convert.ToValue(cfg.InputConfiguration.PassRequestHeaders)
		}
		if v, ok := cfg.Interceptor.(*bacctypes.InterceptorConfigurationMemberLambda); ok {
			ic.lambdaArn = convert.ToValue(v.Value.Arn)
		}
		res = append(res, ic)
	}
	return res
}

func stringsToArrayData(values []string) []any {
	res := make([]any, 0, len(values))
	for _, v := range values {
		res = append(res, v)
	}
	return res
}

// jwtAuthorizerList returns one of the allow lists of a custom JWT authorizer,
// marking the field null when no such authorizer is configured.
func jwtAuthorizerList(jwt *bacctypes.CustomJWTAuthorizerConfiguration, pick func(*bacctypes.CustomJWTAuthorizerConfiguration) []string, field *plugin.TValue[[]any]) ([]any, error) {
	if jwt == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return stringsToArrayData(pick(jwt)), nil
}

func jwtDiscoveryUrl(jwt *bacctypes.CustomJWTAuthorizerConfiguration, field *plugin.TValue[string]) (string, error) {
	if jwt == nil || jwt.DiscoveryUrl == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *jwt.DiscoveryUrl, nil
}

func agentCoreSubnets(runtime *plugin.Runtime, region string, vpc *bacctypes.VpcConfig) ([]any, error) {
	res := []any{}
	if vpc == nil {
		return res, nil
	}
	for _, subnetId := range vpc.Subnets {
		mqlSubnet, err := NewResource(runtime, "aws.vpc.subnet", map[string]*llx.RawData{
			"id":     llx.StringData(subnetId),
			"region": llx.StringData(region),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func agentCoreSecurityGroups(runtime *plugin.Runtime, region string, vpc *bacctypes.VpcConfig) ([]any, error) {
	res := []any{}
	if vpc == nil {
		return res, nil
	}
	conn := runtime.Connection.(*connection.AwsConnection)
	for _, sgId := range vpc.SecurityGroups {
		mqlSg, err := NewResource(runtime, "aws.ec2.securitygroup", map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(securityGroupArnPattern, region, conn.AccountId(), sgId)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSg)
	}
	return res, nil
}

func agentCoreRole(runtime *plugin.Runtime, roleArn *string, field *plugin.TValue[*mqlAwsIamRole]) (*mqlAwsIamRole, error) {
	if convert.ToValue(roleArn) == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "aws.iam.role", map[string]*llx.RawData{"arn": llx.StringDataPtr(roleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

// --- Resource-based policies ---

type agentCorePolicyOutcome int

const (
	agentCorePolicyFailed agentCorePolicyOutcome = iota
	agentCorePolicyAbsent
	agentCorePolicyDenied
)

// classifyAgentCorePolicyError separates a resource that has no policy
// attached from a policy the scan was not allowed to read.
func classifyAgentCorePolicyError(err error) agentCorePolicyOutcome {
	switch {
	case Is400AccessDeniedError(err):
		return agentCorePolicyDenied
	case isResourceNotFoundError(err):
		return agentCorePolicyAbsent
	default:
		return agentCorePolicyFailed
	}
}

// agentCorePolicyCache holds the resource-based policy of an AgentCore
// runtime, runtime endpoint, or gateway. One GetResourcePolicy call feeds
// resourcePolicy, policyStatements and isPublic.
type agentCorePolicyCache struct {
	policyLock       sync.Mutex
	policyFetched    atomic.Bool
	policyText       string
	policyAbsent     bool
	policyUnreadable bool
	policyErr        error
}

func (c *agentCorePolicyCache) loadPolicy(runtime *plugin.Runtime, region, resourceArn string) error {
	if c.policyFetched.Load() {
		return c.policyErr
	}
	c.policyLock.Lock()
	defer c.policyLock.Unlock()
	if c.policyFetched.Load() {
		return c.policyErr
	}
	defer c.policyFetched.Store(true)

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(region)
	resp, err := svc.GetResourcePolicy(context.Background(), &bedrockagentcorecontrol.GetResourcePolicyInput{
		ResourceArn: &resourceArn,
	})
	if err != nil {
		switch classifyAgentCorePolicyError(err) {
		case agentCorePolicyAbsent:
			c.policyAbsent = true
		case agentCorePolicyDenied:
			if plugin.StructuredErrors() {
				c.policyErr = llx.Forbidden(err, llx.WithPermissions("bedrock-agentcore:GetResourcePolicy"))
			} else {
				c.policyUnreadable = true
			}
		default:
			c.policyErr = err
		}
		return c.policyErr
	}
	c.policyText = convert.ToValue(resp.Policy)
	if strings.TrimSpace(c.policyText) == "" {
		c.policyAbsent = true
	}
	return nil
}

func (c *agentCorePolicyCache) policyDocument(runtime *plugin.Runtime, region, resourceArn string, field *plugin.TValue[string]) (string, error) {
	if err := c.loadPolicy(runtime, region, resourceArn); err != nil {
		return "", err
	}
	if c.policyAbsent || c.policyUnreadable {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return c.policyText, nil
}

func (c *agentCorePolicyCache) statementsFromPolicy(runtime *plugin.Runtime, region, resourceArn string, field *plugin.TValue[[]any]) ([]any, error) {
	if err := c.loadPolicy(runtime, region, resourceArn); err != nil {
		return nil, err
	}
	if c.policyUnreadable {
		// An empty list would claim the policy grants nothing; an unread
		// policy supports no such claim.
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if c.policyAbsent {
		return []any{}, nil
	}
	return newPolicyStatementResources(runtime, resourceArn, c.policyText)
}

// --- Runtime ---

func (a *mqlAwsBedrockAgentCoreRuntime) jwtAuthorizer() (*bacctypes.CustomJWTAuthorizerConfiguration, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil {
		return nil, err
	}
	return agentCoreJWTAuthorizer(detail.AuthorizerConfiguration), nil
}

func (a *mqlAwsBedrockAgentCoreRuntime) vpcConfig() (*bacctypes.VpcConfig, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil || detail.NetworkConfiguration == nil {
		return nil, err
	}
	return detail.NetworkConfiguration.NetworkModeConfig, nil
}

func (a *mqlAwsBedrockAgentCoreRuntime) subnets() ([]any, error) {
	vpc, err := a.vpcConfig()
	if err != nil {
		return nil, err
	}
	return agentCoreSubnets(a.MqlRuntime, a.Region.Data, vpc)
}

func (a *mqlAwsBedrockAgentCoreRuntime) securityGroups() ([]any, error) {
	vpc, err := a.vpcConfig()
	if err != nil {
		return nil, err
	}
	return agentCoreSecurityGroups(a.MqlRuntime, a.Region.Data, vpc)
}

func (a *mqlAwsBedrockAgentCoreRuntime) authorizerDiscoveryUrl() (string, error) {
	jwt, err := a.jwtAuthorizer()
	if err != nil {
		return "", err
	}
	return jwtDiscoveryUrl(jwt, &a.AuthorizerDiscoveryUrl)
}

func (a *mqlAwsBedrockAgentCoreRuntime) allowedClients() ([]any, error) {
	jwt, err := a.jwtAuthorizer()
	if err != nil {
		return nil, err
	}
	return jwtAuthorizerList(jwt, func(c *bacctypes.CustomJWTAuthorizerConfiguration) []string { return c.AllowedClients }, &a.AllowedClients)
}

func (a *mqlAwsBedrockAgentCoreRuntime) allowedAudiences() ([]any, error) {
	jwt, err := a.jwtAuthorizer()
	if err != nil {
		return nil, err
	}
	return jwtAuthorizerList(jwt, func(c *bacctypes.CustomJWTAuthorizerConfiguration) []string { return c.AllowedAudience }, &a.AllowedAudiences)
}

func (a *mqlAwsBedrockAgentCoreRuntime) allowedScopes() ([]any, error) {
	jwt, err := a.jwtAuthorizer()
	if err != nil {
		return nil, err
	}
	return jwtAuthorizerList(jwt, func(c *bacctypes.CustomJWTAuthorizerConfiguration) []string { return c.AllowedScopes }, &a.AllowedScopes)
}

func (a *mqlAwsBedrockAgentCoreRuntime) requestHeaderAllowlist() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return []any{}, nil
	}
	return stringsToArrayData(agentCoreRequestHeaderAllowlist(detail.RequestHeaderConfiguration)), nil
}

func (a *mqlAwsBedrockAgentCoreRuntime) resourcePolicy() (string, error) {
	return a.policyDocument(a.MqlRuntime, a.Region.Data, a.Arn.Data, &a.ResourcePolicy)
}

func (a *mqlAwsBedrockAgentCoreRuntime) policyStatements() ([]any, error) {
	return a.statementsFromPolicy(a.MqlRuntime, a.Region.Data, a.Arn.Data, &a.PolicyStatements)
}

func (a *mqlAwsBedrockAgentCoreRuntime) isPublic() (bool, error) {
	return resourceIsPublicOrUnknown(a.GetPolicyStatements(), &a.IsPublic)
}

// --- Runtime endpoint ---

func (a *mqlAwsBedrockAgentCoreRuntimeEndpoint) resourcePolicy() (string, error) {
	return a.policyDocument(a.MqlRuntime, a.Region.Data, a.Arn.Data, &a.ResourcePolicy)
}

func (a *mqlAwsBedrockAgentCoreRuntimeEndpoint) policyStatements() ([]any, error) {
	return a.statementsFromPolicy(a.MqlRuntime, a.Region.Data, a.Arn.Data, &a.PolicyStatements)
}

func (a *mqlAwsBedrockAgentCoreRuntimeEndpoint) isPublic() (bool, error) {
	return resourceIsPublicOrUnknown(a.GetPolicyStatements(), &a.IsPublic)
}

// --- Gateway ---

func (a *mqlAwsBedrockAgentCoreGateway) jwtAuthorizer() (*bacctypes.CustomJWTAuthorizerConfiguration, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil {
		return nil, err
	}
	return agentCoreJWTAuthorizer(detail.AuthorizerConfiguration), nil
}

func (a *mqlAwsBedrockAgentCoreGateway) authorizerDiscoveryUrl() (string, error) {
	jwt, err := a.jwtAuthorizer()
	if err != nil {
		return "", err
	}
	return jwtDiscoveryUrl(jwt, &a.AuthorizerDiscoveryUrl)
}

func (a *mqlAwsBedrockAgentCoreGateway) allowedClients() ([]any, error) {
	jwt, err := a.jwtAuthorizer()
	if err != nil {
		return nil, err
	}
	return jwtAuthorizerList(jwt, func(c *bacctypes.CustomJWTAuthorizerConfiguration) []string { return c.AllowedClients }, &a.AllowedClients)
}

func (a *mqlAwsBedrockAgentCoreGateway) allowedAudiences() ([]any, error) {
	jwt, err := a.jwtAuthorizer()
	if err != nil {
		return nil, err
	}
	return jwtAuthorizerList(jwt, func(c *bacctypes.CustomJWTAuthorizerConfiguration) []string { return c.AllowedAudience }, &a.AllowedAudiences)
}

func (a *mqlAwsBedrockAgentCoreGateway) allowedScopes() ([]any, error) {
	jwt, err := a.jwtAuthorizer()
	if err != nil {
		return nil, err
	}
	return jwtAuthorizerList(jwt, func(c *bacctypes.CustomJWTAuthorizerConfiguration) []string { return c.AllowedScopes }, &a.AllowedScopes)
}

func (a *mqlAwsBedrockAgentCoreGateway) exceptionLevel() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil {
		return "", err
	}
	return string(detail.ExceptionLevel), nil
}

func (a *mqlAwsBedrockAgentCoreGateway) webAcl() (*mqlAwsWafAcl, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || convert.ToValue(detail.WebAclArn) == "" {
		a.WebAcl.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.waf.acl", map[string]*llx.RawData{"arn": llx.StringDataPtr(detail.WebAclArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsWafAcl), nil
}

func (a *mqlAwsBedrockAgentCoreGateway) wafFailureMode() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.WafConfiguration == nil {
		a.WafFailureMode.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(detail.WafConfiguration.FailureMode), nil
}

func (a *mqlAwsBedrockAgentCoreGateway) policyEngineArn() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.PolicyEngineConfiguration == nil || convert.ToValue(detail.PolicyEngineConfiguration.Arn) == "" {
		a.PolicyEngineArn.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *detail.PolicyEngineConfiguration.Arn, nil
}

func (a *mqlAwsBedrockAgentCoreGateway) policyEngineMode() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.PolicyEngineConfiguration == nil {
		a.PolicyEngineMode.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(detail.PolicyEngineConfiguration.Mode), nil
}

func (a *mqlAwsBedrockAgentCoreGateway) interceptors() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	res := []any{}
	if detail == nil {
		return res, nil
	}
	gatewayKey := a.Region.Data + "/" + a.cacheGatewayId
	for i, ic := range agentCoreInterceptors(detail.InterceptorConfigurations) {
		mqlIc, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore.gatewayInterceptor", map[string]*llx.RawData{
			"__id":               llx.StringData(gatewayKey + "/interceptor/" + strconv.Itoa(i)),
			"interceptionPoints": llx.ArrayData(stringsToArrayData(ic.interceptionPoints), types.String),
			"passRequestHeaders": llx.BoolData(ic.passRequestHeaders),
		})
		if err != nil {
			return nil, err
		}
		mqlIc.(*mqlAwsBedrockAgentCoreGatewayInterceptor).cacheLambdaArn = ic.lambdaArn
		res = append(res, mqlIc)
	}
	return res, nil
}

func (a *mqlAwsBedrockAgentCoreGateway) policyArn() (string, error) {
	arn := a.GetArn()
	if arn.Error != nil {
		return "", arn.Error
	}
	return arn.Data, nil
}

func (a *mqlAwsBedrockAgentCoreGateway) resourcePolicy() (string, error) {
	arn, err := a.policyArn()
	if err != nil {
		return "", err
	}
	return a.policyDocument(a.MqlRuntime, a.Region.Data, arn, &a.ResourcePolicy)
}

func (a *mqlAwsBedrockAgentCoreGateway) policyStatements() ([]any, error) {
	arn, err := a.policyArn()
	if err != nil {
		return nil, err
	}
	return a.statementsFromPolicy(a.MqlRuntime, a.Region.Data, arn, &a.PolicyStatements)
}

func (a *mqlAwsBedrockAgentCoreGateway) isPublic() (bool, error) {
	return resourceIsPublicOrUnknown(a.GetPolicyStatements(), &a.IsPublic)
}

type mqlAwsBedrockAgentCoreGatewayInterceptorInternal struct {
	cacheLambdaArn string
}

func (a *mqlAwsBedrockAgentCoreGatewayInterceptor) lambdaFunction() (*mqlAwsLambdaFunction, error) {
	if a.cacheLambdaArn == "" {
		a.LambdaFunction.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.lambda.function", map[string]*llx.RawData{"arn": llx.StringData(a.cacheLambdaArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsLambdaFunction), nil
}

// --- Browser ---

func (a *mqlAwsBedrockAgentCoreBrowser) networkMode() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.NetworkConfiguration == nil {
		a.NetworkMode.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(detail.NetworkConfiguration.NetworkMode), nil
}

func (a *mqlAwsBedrockAgentCoreBrowser) vpcConfig() (*bacctypes.VpcConfig, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil || detail.NetworkConfiguration == nil {
		return nil, err
	}
	return detail.NetworkConfiguration.VpcConfig, nil
}

func (a *mqlAwsBedrockAgentCoreBrowser) subnets() ([]any, error) {
	vpc, err := a.vpcConfig()
	if err != nil {
		return nil, err
	}
	return agentCoreSubnets(a.MqlRuntime, a.Region.Data, vpc)
}

func (a *mqlAwsBedrockAgentCoreBrowser) securityGroups() ([]any, error) {
	vpc, err := a.vpcConfig()
	if err != nil {
		return nil, err
	}
	return agentCoreSecurityGroups(a.MqlRuntime, a.Region.Data, vpc)
}

func (a *mqlAwsBedrockAgentCoreBrowser) iamRole() (*mqlAwsIamRole, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	var roleArn *string
	if detail != nil {
		roleArn = detail.ExecutionRoleArn
	}
	return agentCoreRole(a.MqlRuntime, roleArn, &a.IamRole)
}

func (a *mqlAwsBedrockAgentCoreBrowser) recordingEnabled() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil || detail.Recording == nil {
		return false, err
	}
	return detail.Recording.Enabled, nil
}

func (a *mqlAwsBedrockAgentCoreBrowser) recordingBucket() (*mqlAwsS3Bucket, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	var bucket string
	if detail != nil {
		bucket, _ = agentCoreRecordingLocation(detail.Recording)
	}
	if bucket == "" {
		a.RecordingBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.s3.bucket", map[string]*llx.RawData{"name": llx.StringData(bucket)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsS3Bucket), nil
}

func (a *mqlAwsBedrockAgentCoreBrowser) recordingPrefix() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	var bucket, prefix string
	if detail != nil {
		bucket, prefix = agentCoreRecordingLocation(detail.Recording)
	}
	if bucket == "" {
		a.RecordingPrefix.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return prefix, nil
}

func (a *mqlAwsBedrockAgentCoreBrowser) browserSigningEnabled() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil || detail.BrowserSigning == nil {
		return false, err
	}
	return detail.BrowserSigning.Enabled, nil
}

// --- Code interpreter ---

func (a *mqlAwsBedrockAgentCoreCodeInterpreter) networkMode() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.NetworkConfiguration == nil {
		a.NetworkMode.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(detail.NetworkConfiguration.NetworkMode), nil
}

func (a *mqlAwsBedrockAgentCoreCodeInterpreter) vpcConfig() (*bacctypes.VpcConfig, error) {
	detail, err := a.fetchDetail()
	if err != nil || detail == nil || detail.NetworkConfiguration == nil {
		return nil, err
	}
	return detail.NetworkConfiguration.VpcConfig, nil
}

func (a *mqlAwsBedrockAgentCoreCodeInterpreter) subnets() ([]any, error) {
	vpc, err := a.vpcConfig()
	if err != nil {
		return nil, err
	}
	return agentCoreSubnets(a.MqlRuntime, a.Region.Data, vpc)
}

func (a *mqlAwsBedrockAgentCoreCodeInterpreter) securityGroups() ([]any, error) {
	vpc, err := a.vpcConfig()
	if err != nil {
		return nil, err
	}
	return agentCoreSecurityGroups(a.MqlRuntime, a.Region.Data, vpc)
}

func (a *mqlAwsBedrockAgentCoreCodeInterpreter) iamRole() (*mqlAwsIamRole, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	var roleArn *string
	if detail != nil {
		roleArn = detail.ExecutionRoleArn
	}
	return agentCoreRole(a.MqlRuntime, roleArn, &a.IamRole)
}
