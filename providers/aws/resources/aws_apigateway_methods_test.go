// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestApigatewayMethodSpecs(t *testing.T) {
	specs := apigatewayMethodSpecs(map[string]types.Method{
		"POST": {
			HttpMethod:          aws.String("POST"),
			AuthorizationType:   aws.String("COGNITO_USER_POOLS"),
			AuthorizerId:        aws.String("auth1"),
			AuthorizationScopes: []string{"orders/write"},
			RequestValidatorId:  aws.String("val1"),
			MethodIntegration: &types.Integration{
				Type:           types.IntegrationTypeAwsProxy,
				ConnectionType: types.ConnectionTypeVpcLink,
			},
		},
		// The map key is the verb; a method without HttpMethod falls back to it.
		"GET": {
			AuthorizationType: aws.String("NONE"),
			ApiKeyRequired:    aws.Bool(true),
		},
	})
	require.Len(t, specs, 2)

	get := specs[0]
	assert.Equal(t, "GET", get.httpMethod, "methods are ordered by verb")
	assert.Equal(t, "NONE", get.authorizationType)
	assert.True(t, get.apiKeyRequired)
	assert.Empty(t, get.authorizerID)
	assert.Nil(t, get.integrationType, "a method without integration reports null")
	assert.Nil(t, get.integrationConnectionType)
	assert.Equal(t, []any{}, get.authorizationScopes)

	post := specs[1]
	assert.Equal(t, "POST", post.httpMethod)
	assert.False(t, post.apiKeyRequired)
	assert.Equal(t, "auth1", post.authorizerID)
	assert.Equal(t, "val1", post.requestValidatorID)
	assert.Equal(t, []any{"orders/write"}, post.authorizationScopes)
	require.NotNil(t, post.integrationType)
	assert.Equal(t, "AWS_PROXY", *post.integrationType)
	require.NotNil(t, post.integrationConnectionType)
	assert.Equal(t, "VPC_LINK", *post.integrationConnectionType)
}

func TestApigatewayMethodAuthorizerResolvesFromApiList(t *testing.T) {
	rt := testRuntime()
	api := &mqlAwsApigatewayRestapi{MqlRuntime: rt}
	api.Authorizers = plugin.TValue[[]any]{
		Data: []any{
			&mqlAwsApigatewayAuthorizer{Id: setString("other")},
			&mqlAwsApigatewayAuthorizer{Id: setString("auth1"), Name: setString("cognito")},
		},
		State: plugin.StateIsSet,
	}

	m := &mqlAwsApigatewayMethod{MqlRuntime: rt}
	m.restApi = api
	m.cacheAuthorizerId = "auth1"
	auth, err := m.authorizer()
	require.NoError(t, err)
	require.NotNil(t, auth)
	assert.Equal(t, "cognito", auth.Name.Data)

	none := &mqlAwsApigatewayMethod{MqlRuntime: rt}
	none.restApi = api
	auth, err = none.authorizer()
	require.NoError(t, err)
	assert.Nil(t, auth)
	assert.True(t, none.Authorizer.IsNull(), "a method without an authorizer reads null")

	missing := &mqlAwsApigatewayMethod{MqlRuntime: rt}
	missing.restApi = api
	missing.cacheAuthorizerId = "gone"
	auth, err = missing.authorizer()
	require.NoError(t, err)
	assert.Nil(t, auth)
	assert.True(t, missing.Authorizer.IsNull())
}

func TestApigatewayResourcesDeniedIsNull(t *testing.T) {
	rt := testRuntime()
	calls := 0
	rt.Connection = stubAwsConn(t, func(params any) (any, error) {
		calls++
		return nil, awsAPIErr(403, "AccessDeniedException", "not authorized to perform apigateway:GET")
	})
	api := &mqlAwsApigatewayRestapi{MqlRuntime: rt, Id: setString("abc123"), Region: setString("us-east-1")}

	res, err := api.resources()
	require.NoError(t, err)
	assert.Nil(t, res)
	assert.True(t, api.Resources.IsNull(), "a refused read is null, not an empty list")

	methods, err := api.methods()
	require.NoError(t, err)
	assert.Nil(t, methods)
	assert.True(t, api.Methods.IsNull())
	assert.Equal(t, 1, calls, "methods reuses the refused read")
}
