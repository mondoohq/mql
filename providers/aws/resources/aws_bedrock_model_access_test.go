// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	"github.com/stretchr/testify/assert"
)

func TestFoundationModelRegion(t *testing.T) {
	// Synthetic: foundation model ARNs carry the region and no account.
	assert.Equal(t, "eu-central-1", foundationModelRegion("arn:aws:bedrock:eu-central-1::foundation-model/amazon.titan-embed-text-v2:0"))
	assert.Empty(t, foundationModelRegion("amazon.titan-embed-text-v2:0"))
}

func TestAvailabilityBool(t *testing.T) {
	// Synthetic: both states and the unset case.
	v, ok := availabilityBool(bedrocktypes.AuthorizationStatusAuthorized, bedrocktypes.AuthorizationStatusAuthorized)
	assert.True(t, ok)
	assert.True(t, v)

	v, ok = availabilityBool(bedrocktypes.AuthorizationStatusNotAuthorized, bedrocktypes.AuthorizationStatusAuthorized)
	assert.True(t, ok)
	assert.False(t, v)

	_, ok = availabilityBool(bedrocktypes.RegionAvailability(""), bedrocktypes.RegionAvailabilityAvailable)
	assert.False(t, ok, "an unset status is null, not false")
}

func TestPromptRouterModelArns(t *testing.T) {
	// Synthetic: a nil target model ARN is skipped.
	got := promptRouterModelArns([]bedrocktypes.PromptRouterTargetModel{
		{ModelArn: aws.String("arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-haiku")},
		{ModelArn: nil},
		{ModelArn: aws.String("arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-sonnet")},
	})
	assert.Equal(t, []any{
		"arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-haiku",
		"arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-sonnet",
	}, got)
	assert.Equal(t, []any{}, promptRouterModelArns(nil))
}
