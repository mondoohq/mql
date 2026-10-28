// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	bacctypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Synthetic: no AgentCore resources existed in a test account; shapes follow
// the bedrockagentcorecontrol v1.75.0 types.

func TestAgentCoreJWTAuthorizer(t *testing.T) {
	t.Run("custom JWT authorizer", func(t *testing.T) {
		// Synthetic: a runtime that accepts tokens from one Cognito pool.
		cfg := &bacctypes.AuthorizerConfigurationMemberCustomJWTAuthorizer{
			Value: bacctypes.CustomJWTAuthorizerConfiguration{
				DiscoveryUrl:    aws.String("https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc/.well-known/openid-configuration"),
				AllowedClients:  []string{"client-a", "client-b"},
				AllowedAudience: []string{"aud-1"},
				AllowedScopes:   []string{"invoke"},
			},
		}
		jwt := agentCoreJWTAuthorizer(cfg)
		require.NotNil(t, jwt)

		var urlField plugin.TValue[string]
		url, err := jwtDiscoveryUrl(jwt, &urlField)
		require.NoError(t, err)
		assert.Equal(t, "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc/.well-known/openid-configuration", url)
		assert.False(t, urlField.IsNull())

		var clientsField, audField, scopesField plugin.TValue[[]any]
		clients, _ := jwtAuthorizerList(jwt, func(c *bacctypes.CustomJWTAuthorizerConfiguration) []string { return c.AllowedClients }, &clientsField)
		assert.Equal(t, []any{"client-a", "client-b"}, clients)
		aud, _ := jwtAuthorizerList(jwt, func(c *bacctypes.CustomJWTAuthorizerConfiguration) []string { return c.AllowedAudience }, &audField)
		assert.Equal(t, []any{"aud-1"}, aud)
		scopes, _ := jwtAuthorizerList(jwt, func(c *bacctypes.CustomJWTAuthorizerConfiguration) []string { return c.AllowedScopes }, &scopesField)
		assert.Equal(t, []any{"invoke"}, scopes)
	})

	t.Run("JWT authorizer with no client restriction is empty, not null", func(t *testing.T) {
		// Synthetic: an authorizer that checks only the issuer.
		jwt := agentCoreJWTAuthorizer(&bacctypes.AuthorizerConfigurationMemberCustomJWTAuthorizer{
			Value: bacctypes.CustomJWTAuthorizerConfiguration{DiscoveryUrl: aws.String("https://issuer.example/.well-known/openid-configuration")},
		})
		require.NotNil(t, jwt)
		var field plugin.TValue[[]any]
		clients, err := jwtAuthorizerList(jwt, func(c *bacctypes.CustomJWTAuthorizerConfiguration) []string { return c.AllowedClients }, &field)
		require.NoError(t, err)
		assert.Equal(t, []any{}, clients)
		assert.False(t, field.IsNull())
	})

	t.Run("IAM SigV4 runtime has no JWT authorizer, fields are null", func(t *testing.T) {
		// Synthetic: GetAgentRuntime omits authorizerConfiguration under IAM auth.
		jwt := agentCoreJWTAuthorizer(nil)
		assert.Nil(t, jwt)

		var urlField plugin.TValue[string]
		_, err := jwtDiscoveryUrl(jwt, &urlField)
		require.NoError(t, err)
		assert.True(t, urlField.IsNull())

		var listField plugin.TValue[[]any]
		list, err := jwtAuthorizerList(jwt, func(c *bacctypes.CustomJWTAuthorizerConfiguration) []string { return c.AllowedClients }, &listField)
		require.NoError(t, err)
		assert.Nil(t, list)
		assert.True(t, listField.IsNull())
	})
}

func TestAgentCoreRequestHeaderAllowlist(t *testing.T) {
	// Synthetic: a runtime forwarding the Authorization header to agent code.
	got := agentCoreRequestHeaderAllowlist(&bacctypes.RequestHeaderConfigurationMemberRequestHeaderAllowlist{
		Value: []string{"Authorization", "X-Amzn-Bedrock-AgentCore-Runtime-Custom-Tenant"},
	})
	assert.Equal(t, []string{"Authorization", "X-Amzn-Bedrock-AgentCore-Runtime-Custom-Tenant"}, got)

	// Synthetic: no request header configuration.
	assert.Empty(t, agentCoreRequestHeaderAllowlist(nil))
	assert.Equal(t, []any{}, stringsToArrayData(agentCoreRequestHeaderAllowlist(nil)))
}

func TestAgentCoreRecordingLocation(t *testing.T) {
	// Synthetic: recording into a bucket under a prefix.
	bucket, prefix := agentCoreRecordingLocation(&bacctypes.RecordingConfig{
		Enabled:    true,
		S3Location: &bacctypes.S3Location{Bucket: aws.String("agent-recordings"), Prefix: aws.String("browser/")},
	})
	assert.Equal(t, "agent-recordings", bucket)
	assert.Equal(t, "browser/", prefix)

	// Synthetic: recording configured without a location.
	bucket, prefix = agentCoreRecordingLocation(&bacctypes.RecordingConfig{Enabled: false})
	assert.Empty(t, bucket)
	assert.Empty(t, prefix)

	// Synthetic: no recording configuration at all.
	bucket, prefix = agentCoreRecordingLocation(nil)
	assert.Empty(t, bucket)
	assert.Empty(t, prefix)
}

func TestAgentCoreInterceptors(t *testing.T) {
	// Synthetic: one Lambda interceptor on both points that sees request
	// headers, one on responses only with no input configuration.
	got := agentCoreInterceptors([]bacctypes.GatewayInterceptorConfiguration{
		{
			InterceptionPoints: []bacctypes.GatewayInterceptionPoint{bacctypes.GatewayInterceptionPointRequest, bacctypes.GatewayInterceptionPointResponse},
			Interceptor: &bacctypes.InterceptorConfigurationMemberLambda{
				Value: bacctypes.LambdaInterceptorConfiguration{Arn: aws.String("arn:aws:lambda:us-east-1:123456789012:function:inspect")},
			},
			InputConfiguration: &bacctypes.InterceptorInputConfiguration{PassRequestHeaders: aws.Bool(true)},
		},
		{
			InterceptionPoints: []bacctypes.GatewayInterceptionPoint{bacctypes.GatewayInterceptionPointResponse},
		},
	})
	require.Len(t, got, 2)
	assert.Equal(t, []string{"REQUEST", "RESPONSE"}, got[0].interceptionPoints)
	assert.True(t, got[0].passRequestHeaders)
	assert.Equal(t, "arn:aws:lambda:us-east-1:123456789012:function:inspect", got[0].lambdaArn)

	assert.Equal(t, []string{"RESPONSE"}, got[1].interceptionPoints)
	assert.False(t, got[1].passRequestHeaders)
	assert.Empty(t, got[1].lambdaArn)

	assert.Empty(t, agentCoreInterceptors(nil))
}

func TestClassifyAgentCorePolicyError(t *testing.T) {
	// Synthetic: error shapes as the SDK returns them.
	assert.Equal(t, agentCorePolicyDenied, classifyAgentCorePolicyError(
		awsAPIErr(403, "AccessDeniedException", "User is not authorized to perform: bedrock-agentcore:GetResourcePolicy")))
	assert.Equal(t, agentCorePolicyAbsent, classifyAgentCorePolicyError(
		awsAPIErr(404, "ResourceNotFoundException", "No resource policy found")))
	assert.Equal(t, agentCorePolicyFailed, classifyAgentCorePolicyError(
		awsAPIErr(500, "InternalServerException", "boom")))
	assert.Equal(t, agentCorePolicyFailed, classifyAgentCorePolicyError(errors.New("dial tcp: connection refused")))
}

// preloaded returns a policy cache that already holds a fetch outcome, so the
// accessors can be exercised without a connection.
func preloaded(c agentCorePolicyCache) *agentCorePolicyCache {
	res := &agentCorePolicyCache{
		policyText:       c.policyText,
		policyAbsent:     c.policyAbsent,
		policyUnreadable: c.policyUnreadable,
		policyErr:        c.policyErr,
	}
	res.policyFetched.Store(true)
	return res
}

func TestAgentCorePolicyCacheOutcomes(t *testing.T) {
	const arn = "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/rt-1"

	t.Run("no policy attached: document null, statements empty, not public", func(t *testing.T) {
		// Synthetic: GetResourcePolicy reports no policy.
		c := preloaded(agentCorePolicyCache{policyAbsent: true})
		var doc plugin.TValue[string]
		_, err := c.policyDocument(nil, "us-east-1", arn, &doc)
		require.NoError(t, err)
		assert.True(t, doc.IsNull())

		var stmtsField plugin.TValue[[]any]
		stmts, err := c.statementsFromPolicy(nil, "us-east-1", arn, &stmtsField)
		require.NoError(t, err)
		assert.Equal(t, []any{}, stmts)
		assert.False(t, stmtsField.IsNull())

		var isPublic plugin.TValue[bool]
		stmtsField.Data, stmtsField.State = stmts, plugin.StateIsSet
		public, err := resourceIsPublicOrUnknown(&stmtsField, &isPublic)
		require.NoError(t, err)
		assert.False(t, public)
		assert.False(t, isPublic.IsNull())
	})

	t.Run("denied read: document, statements and isPublic are null", func(t *testing.T) {
		// Synthetic: GetResourcePolicy refused, structured errors off.
		c := preloaded(agentCorePolicyCache{policyUnreadable: true})
		var doc plugin.TValue[string]
		_, err := c.policyDocument(nil, "us-east-1", arn, &doc)
		require.NoError(t, err)
		assert.True(t, doc.IsNull())

		var stmtsField plugin.TValue[[]any]
		stmts, err := c.statementsFromPolicy(nil, "us-east-1", arn, &stmtsField)
		require.NoError(t, err)
		assert.Nil(t, stmts)
		assert.True(t, stmtsField.IsNull())

		var isPublic plugin.TValue[bool]
		_, err = resourceIsPublicOrUnknown(&stmtsField, &isPublic)
		require.NoError(t, err)
		assert.True(t, isPublic.IsNull())
	})

	t.Run("policy attached: document returned verbatim", func(t *testing.T) {
		// Synthetic: a policy granting invoke to one account.
		policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"bedrock-agentcore:InvokeAgentRuntime","Resource":"*"}]}`
		c := preloaded(agentCorePolicyCache{policyText: policy})
		var doc plugin.TValue[string]
		got, err := c.policyDocument(nil, "us-east-1", arn, &doc)
		require.NoError(t, err)
		assert.Equal(t, policy, got)
		assert.False(t, doc.IsNull())
	})

	t.Run("failed read is an error on every field", func(t *testing.T) {
		// Synthetic: a transport failure is cached and repeated.
		boom := errors.New("connection reset")
		c := preloaded(agentCorePolicyCache{policyErr: boom})
		var doc plugin.TValue[string]
		_, err := c.policyDocument(nil, "us-east-1", arn, &doc)
		assert.ErrorIs(t, err, boom)
		var stmtsField plugin.TValue[[]any]
		_, err = c.statementsFromPolicy(nil, "us-east-1", arn, &stmtsField)
		assert.ErrorIs(t, err, boom)
	})
}
