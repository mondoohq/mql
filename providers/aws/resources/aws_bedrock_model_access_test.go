// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	nethttp "net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
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

func TestBedrockTargetKind(t *testing.T) {
	// Synthetic: ARN shapes from the Bedrock prompt router and inference profile docs.
	assert.Equal(t, "foundationModel", bedrockTargetKind("arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"))
	assert.Equal(t, "inferenceProfile", bedrockTargetKind("arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-3-haiku-20240307-v1:0"))
	assert.Equal(t, "inferenceProfile", bedrockTargetKind("arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/abc123"))
	assert.Empty(t, bedrockTargetKind("arn:aws:bedrock:us-east-1:123456789012:prompt-router/xyz"))
	assert.Empty(t, bedrockTargetKind("anthropic.claude-3-haiku-20240307-v1:0"))
	assert.Empty(t, bedrockTargetKind(""))
}

func TestIsBedrockRegionUnsupported(t *testing.T) {
	// Measured: ListPromptRouters responses from regions without prompt routers, 2026-11-06.
	assert.True(t, isBedrockRegionUnsupported(&smithy.GenericAPIError{Code: "ValidationException", Message: "The requested operation is not recognized by the service."}))
	assert.True(t, isBedrockRegionUnsupported(&smithy.GenericAPIError{Code: "ValidationException", Message: "You don't have the permissions to perform the requested operation."}))
	// Measured: ListCustomModelDeployments answers 404 with an HTML body in a region without the API, 2026-11-06.
	assert.True(t, isBedrockRegionUnsupported(&smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &nethttp.Response{StatusCode: 404}},
		Err:      errors.New("deserialization failed, failed to decode response body"),
	}))
	// Synthetic: a real refusal, another validation error and a transport error are not region gaps.
	assert.False(t, isBedrockRegionUnsupported(&smithy.GenericAPIError{Code: "AccessDeniedException", Message: "User is not authorized"}))
	assert.False(t, isBedrockRegionUnsupported(&smithy.GenericAPIError{Code: "ValidationException", Message: "1 validation error detected: maxResults"}))
	assert.False(t, isBedrockRegionUnsupported(&smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &nethttp.Response{StatusCode: 500}},
		Err:      errors.New("internal"),
	}))
	assert.False(t, isBedrockRegionUnsupported(errors.New("dial tcp: connection refused")))
}
