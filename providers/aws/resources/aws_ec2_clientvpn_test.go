// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientVpnDeviceTrustProviders(t *testing.T) {
	t.Run("no device posture options is an empty list, not null", func(t *testing.T) {
		res := clientVpnDeviceTrustProviders(nil)
		require.NotNil(t, res)
		assert.Empty(t, res)
	})

	t.Run("posture options without providers is empty", func(t *testing.T) {
		res := clientVpnDeviceTrustProviders(&ec2types.DevicePostureResponseOptions{})
		require.NotNil(t, res)
		assert.Empty(t, res)
	})

	t.Run("each provider maps to its own keys", func(t *testing.T) {
		res := clientVpnDeviceTrustProviders(&ec2types.DevicePostureResponseOptions{
			TrustProviders: []ec2types.ClientVpnTrustProvider{
				{
					TrustProviderType:   ec2types.ClientVpnDeviceTrustProviderTypeCrowdstrike,
					TenantId:            aws.String("tenant-1"),
					PublicSigningKeyUrl: aws.String("https://keys.example.com/jwks"),
				},
				{
					// nil pointers must read as empty strings, not panic
					TrustProviderType: ec2types.ClientVpnDeviceTrustProviderTypeJamf,
				},
			},
		})
		require.Len(t, res, 2)
		assert.Equal(t, map[string]any{
			"trustProviderType":   "crowdstrike",
			"tenantId":            "tenant-1",
			"publicSigningKeyUrl": "https://keys.example.com/jwks",
		}, res[0])
		assert.Equal(t, map[string]any{
			"trustProviderType":   "jamf",
			"tenantId":            "",
			"publicSigningKeyUrl": "",
		}, res[1])
	})
}

func TestNewClientVpnAuthorizationPolicy(t *testing.T) {
	t.Run("nil output is no policy", func(t *testing.T) {
		assert.Nil(t, newClientVpnAuthorizationPolicy(nil))
	})

	t.Run("output without document or status is no policy", func(t *testing.T) {
		assert.Nil(t, newClientVpnAuthorizationPolicy(&ec2.GetClientVpnEndpointAuthorizationPolicyOutput{
			ClientVpnEndpointId: aws.String("cvpn-endpoint-0123"),
		}))
	})

	t.Run("enforced policy", func(t *testing.T) {
		p := newClientVpnAuthorizationPolicy(&ec2.GetClientVpnEndpointAuthorizationPolicyOutput{
			PolicyDocument: aws.String("permit(principal, action, resource);"),
			Status:         ec2types.ClientVpnAuthorizationPolicyStatusActive,
			ShadowMode:     ec2types.ClientVpnAuthorizationPolicyShadowModeDisabled,
		})
		require.NotNil(t, p)
		assert.Equal(t, "permit(principal, action, resource);", p.document)
		assert.Equal(t, "active", p.status)
		require.NotNil(t, p.inShadowMode)
		assert.False(t, *p.inShadowMode)
	})

	t.Run("policy being created has a status but no document yet", func(t *testing.T) {
		p := newClientVpnAuthorizationPolicy(&ec2.GetClientVpnEndpointAuthorizationPolicyOutput{
			Status:     ec2types.ClientVpnAuthorizationPolicyStatusCreating,
			ShadowMode: ec2types.ClientVpnAuthorizationPolicyShadowModeEnabled,
		})
		require.NotNil(t, p)
		assert.Equal(t, "", p.document)
		assert.Equal(t, "creating", p.status)
		require.NotNil(t, p.inShadowMode)
		assert.True(t, *p.inShadowMode)
	})
}

func TestClientVpnShadowModeEnabled(t *testing.T) {
	enabled := clientVpnShadowModeEnabled(ec2types.ClientVpnAuthorizationPolicyShadowModeEnabled)
	require.NotNil(t, enabled)
	assert.True(t, *enabled)

	disabled := clientVpnShadowModeEnabled(ec2types.ClientVpnAuthorizationPolicyShadowModeDisabled)
	require.NotNil(t, disabled)
	assert.False(t, *disabled)

	assert.Nil(t, clientVpnShadowModeEnabled(""), "absent shadow mode is null, not false")
	assert.Nil(t, clientVpnShadowModeEnabled("audit"), "unknown shadow mode is null, not a guess")
}

func TestIsClientVpnAuthorizationPolicyNotFound(t *testing.T) {
	notFound := &smithy.GenericAPIError{Code: "InvalidClientVpnEndpointAuthorizationPolicy.NotFound", Message: "no policy"}
	assert.True(t, isClientVpnAuthorizationPolicyNotFound(notFound))
	assert.True(t, isClientVpnAuthorizationPolicyNotFound(fmt.Errorf("operation error EC2: %w", notFound)), "wrapped errors match")

	assert.False(t, isClientVpnAuthorizationPolicyNotFound(
		&smithy.GenericAPIError{Code: "InvalidClientVpnEndpointId.NotFound"}),
		"a missing endpoint does not establish that there is no policy")
	assert.False(t, isClientVpnAuthorizationPolicyNotFound(
		&smithy.GenericAPIError{Code: "UnauthorizedOperation"}))
	assert.False(t, isClientVpnAuthorizationPolicyNotFound(
		errors.New("InvalidClientVpnEndpointAuthorizationPolicy.NotFound: dial tcp: connection refused")),
		"a transport error carrying the text is not an API answer")
	assert.False(t, isClientVpnAuthorizationPolicyNotFound(nil))
}
