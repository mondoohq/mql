// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
)

func TestIsSecurityHubCentralConfigUnavailable(t *testing.T) {
	// Measured: ListConfigurationPolicies and ListConfigurationPolicyAssociations
	// in us-east-1 of an organization member account, 2026-10-27.
	measured := &types.AccessDeniedException{
		Message: aws.String("Must be a Security Hub delegated administrator with Central Configuration enabled"),
	}
	assert.True(t, isSecurityHubCentralConfigUnavailable(fmt.Errorf("op: %w", measured)))

	// Measured: DescribeHub in a region where Security Hub is not enabled
	// answered InvalidAccessException, 2026-10-27.
	assert.True(t, isSecurityHubCentralConfigUnavailable(&types.InvalidAccessException{
		Message: aws.String("Account is not subscribed to AWS Security Hub CSPM"),
	}))

	// Synthetic: an IAM denial names the action, and stays Forbidden.
	assert.False(t, isSecurityHubCentralConfigUnavailable(&types.AccessDeniedException{
		Message: aws.String("User: arn:aws:iam::000000000000:user/x is not authorized to perform: securityhub:ListConfigurationPolicies"),
	}))
	// Synthetic: the message alone does not qualify an unrelated code.
	assert.False(t, isSecurityHubCentralConfigUnavailable(&smithy.GenericAPIError{
		Code:    "ThrottlingException",
		Message: "delegated administrator rate exceeded",
	}))
	assert.False(t, isSecurityHubCentralConfigUnavailable(nil))
}

func TestDecodeSecurityHubPolicy(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	// Synthetic: shapes from the GetConfigurationPolicy API reference; the
	// test account is not a Security Hub delegated administrator.
	t.Run("enabled controls with parameters", func(t *testing.T) {
		d := decodeSecurityHubPolicy(&securityhub.GetConfigurationPolicyOutput{
			CreatedAt: &created,
			ConfigurationPolicy: &types.PolicyMemberSecurityHub{Value: types.SecurityHubPolicy{
				ServiceEnabled:             aws.Bool(true),
				EnabledStandardIdentifiers: []string{"arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"},
				SecurityControlsConfiguration: &types.SecurityControlsConfiguration{
					EnabledSecurityControlIdentifiers: []string{"IAM.1", "ACM.1"},
					SecurityControlCustomParameters: []types.SecurityControlCustomParameter{
						{
							SecurityControlId: aws.String("ACM.1"),
							Parameters: map[string]types.ParameterConfiguration{
								"daysToExpiration": {
									ValueType: types.ParameterValueTypeCustom,
									Value:     &types.ParameterValueMemberInteger{Value: 15},
								},
								"other": {ValueType: types.ParameterValueTypeDefault},
							},
						},
						{Parameters: map[string]types.ParameterConfiguration{}},
					},
				},
			}},
		})
		assert.Equal(t, &created, d.createdAt)
		assert.Equal(t, []any{"arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"}, d.enabledStandards)
		assert.Equal(t, []any{"IAM.1", "ACM.1"}, d.enabledControls)
		assert.Nil(t, d.disabledControls)
		assert.Equal(t, map[string]any{
			"ACM.1": map[string]any{
				"daysToExpiration": map[string]any{"valueType": "CUSTOM", "value": int64(15)},
				"other":            map[string]any{"valueType": "DEFAULT", "value": nil},
			},
		}, d.controlParameters)
	})

	t.Run("disabled controls, empty list kept", func(t *testing.T) {
		d := decodeSecurityHubPolicy(&securityhub.GetConfigurationPolicyOutput{
			ConfigurationPolicy: &types.PolicyMemberSecurityHub{Value: types.SecurityHubPolicy{
				SecurityControlsConfiguration: &types.SecurityControlsConfiguration{
					DisabledSecurityControlIdentifiers: []string{},
				},
			}},
		})
		assert.Nil(t, d.enabledControls)
		assert.NotNil(t, d.disabledControls)
		assert.Empty(t, d.disabledControls)
		assert.Equal(t, []any{}, d.enabledStandards)
	})

	t.Run("no policy body", func(t *testing.T) {
		d := decodeSecurityHubPolicy(&securityhub.GetConfigurationPolicyOutput{})
		assert.Nil(t, d.createdAt)
		assert.Equal(t, []any{}, d.enabledStandards)
		assert.Nil(t, d.enabledControls)
		assert.Nil(t, d.disabledControls)
		assert.Equal(t, map[string]any{}, d.controlParameters)
	})
}

func TestSecurityHubParameterValue(t *testing.T) {
	tests := []struct {
		name string
		in   types.ParameterValue
		want any
	}{
		{"boolean", &types.ParameterValueMemberBoolean{Value: true}, true},
		{"double", &types.ParameterValueMemberDouble{Value: 1.5}, 1.5},
		{"enum", &types.ParameterValueMemberEnum{Value: "ALL"}, "ALL"},
		{"enum list", &types.ParameterValueMemberEnumList{Value: []string{"a", "b"}}, []any{"a", "b"}},
		{"integer", &types.ParameterValueMemberInteger{Value: 90}, int64(90)},
		{"integer list", &types.ParameterValueMemberIntegerList{Value: []int32{1, 2}}, []any{int64(1), int64(2)}},
		{"string", &types.ParameterValueMemberString{Value: "x"}, "x"},
		{"string list", &types.ParameterValueMemberStringList{Value: []string{"x"}}, []any{"x"}},
		{"absent", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, securityHubParameterValue(tt.in))
		})
	}
}
