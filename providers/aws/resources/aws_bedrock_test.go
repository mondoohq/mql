// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

func TestEnumSliceToAny(t *testing.T) {
	t.Run("empty slice returns empty", func(t *testing.T) {
		result := enumSliceToAny([]bedrocktypes.ModelModality{})
		assert.Empty(t, result)
	})

	t.Run("converts modalities to string slice", func(t *testing.T) {
		modalities := []bedrocktypes.ModelModality{"TEXT", "IMAGE", "EMBEDDING"}
		result := enumSliceToAny(modalities)
		assert.Equal(t, []any{"TEXT", "IMAGE", "EMBEDDING"}, result)
	})

	t.Run("converts customization types", func(t *testing.T) {
		types := []bedrocktypes.ModelCustomization{"FINE_TUNING", "CONTINUED_PRE_TRAINING"}
		result := enumSliceToAny(types)
		assert.Equal(t, []any{"FINE_TUNING", "CONTINUED_PRE_TRAINING"}, result)
	})

	t.Run("nil slice returns empty", func(t *testing.T) {
		var s []bedrocktypes.InferenceType
		result := enumSliceToAny(s)
		assert.Empty(t, result)
	})
}

// TestBedrockCustomModelArgsAreSettableFields pins every argument the custom
// model init passes to a field the generated schema can actually set.
// SetAllData rejects an unknown key outright, so a stale argument left behind
// by a schema change does not degrade a field - it fails the whole resource on
// every typed reference, because this init runs on every NewResource for the
// type.
func TestBedrockCustomModelArgsAreSettableFields(t *testing.T) {
	args := bedrockCustomModelArgs(
		aws.String("arn:aws:bedrock:us-east-1:123456789012:custom-model/anthropic.claude/abc"),
		aws.String("tuned-claude"),
		"us-east-1",
		bedrocktypes.CustomizationTypeFineTuning,
	)

	require.NotEmpty(t, args)
	for key := range args {
		if key == "__id" {
			continue
		}
		_, ok := setDataFields["aws.bedrock.customModel."+key]
		assert.True(t, ok, "aws.bedrock.customModel has no settable field %q", key)
	}

	// The base model reaches the resource through the typed baseModel
	// accessor, never as a raw ARN argument.
	assert.NotContains(t, args, "baseModelArn")
}

func TestBedrockLoggingDestinationsFrom(t *testing.T) {
	// Synthetic: no logging configuration in the region.
	t.Run("nil config", func(t *testing.T) {
		assert.Equal(t, bedrockLoggingDestinations{}, bedrockLoggingDestinationsFrom(nil))
	})

	// Synthetic: S3 delivery only; CloudWatch destinations stay empty.
	t.Run("s3 only", func(t *testing.T) {
		got := bedrockLoggingDestinationsFrom(&bedrocktypes.LoggingConfig{
			S3Config: &bedrocktypes.S3Config{BucketName: aws.String("invocation-logs"), KeyPrefix: aws.String("bedrock/")},
		})
		assert.Equal(t, bedrockLoggingDestinations{s3BucketName: "invocation-logs"}, got)
	})

	// Synthetic: CloudWatch delivery with a large-data overflow bucket, which
	// must not be confused with the S3 delivery bucket.
	t.Run("cloudwatch with large data bucket", func(t *testing.T) {
		got := bedrockLoggingDestinationsFrom(&bedrocktypes.LoggingConfig{
			CloudWatchConfig: &bedrocktypes.CloudWatchConfig{
				LogGroupName:              aws.String("/bedrock/invocations"),
				RoleArn:                   aws.String("arn:aws:iam::123456789012:role/bedrock-logging"),
				LargeDataDeliveryS3Config: &bedrocktypes.S3Config{BucketName: aws.String("large-payloads")},
			},
		})
		assert.Equal(t, bedrockLoggingDestinations{
			logGroupName:      "/bedrock/invocations",
			roleArn:           "arn:aws:iam::123456789012:role/bedrock-logging",
			largeDataS3Bucket: "large-payloads",
		}, got)
	})

	// Synthetic: CloudWatch delivery without a large-data location.
	t.Run("cloudwatch without large data bucket", func(t *testing.T) {
		got := bedrockLoggingDestinationsFrom(&bedrocktypes.LoggingConfig{
			CloudWatchConfig: &bedrocktypes.CloudWatchConfig{LogGroupName: aws.String("lg")},
			S3Config:         &bedrocktypes.S3Config{BucketName: aws.String("b")},
		})
		assert.Equal(t, bedrockLoggingDestinations{logGroupName: "lg", s3BucketName: "b"}, got)
	})
}

func TestIsBedrockCustomModelArn(t *testing.T) {
	tests := []struct {
		name string
		arn  string
		want bool
	}{
		// Synthetic: the ARN shapes Bedrock documents for each model kind.
		{"custom model", "arn:aws:bedrock:us-east-1:123456789012:custom-model/amazon.titan-text-express-v1:0:8k/abc123", true},
		{"foundation model", "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-v2", false},
		{"imported model", "arn:aws:bedrock:us-east-1:123456789012:imported-model/abc123", false},
		{"other service", "arn:aws:sagemaker:us-east-1:123456789012:custom-model/x", false},
		{"not an arn", "custom-model/x", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isBedrockCustomModelArn(tt.arn))
		})
	}
}

func TestBatchInferenceJobLocationsFrom(t *testing.T) {
	// Synthetic: S3 input and output with a customer-managed output key.
	t.Run("s3 input and encrypted output", func(t *testing.T) {
		got := batchInferenceJobLocationsFrom(
			&bedrocktypes.ModelInvocationJobInputDataConfigMemberS3InputDataConfig{
				Value: bedrocktypes.ModelInvocationJobS3InputDataConfig{S3Uri: aws.String("s3://batch-in/records.jsonl")},
			},
			&bedrocktypes.ModelInvocationJobOutputDataConfigMemberS3OutputDataConfig{
				Value: bedrocktypes.ModelInvocationJobS3OutputDataConfig{
					S3Uri:             aws.String("s3://batch-out/results/"),
					S3EncryptionKeyId: aws.String("alias/batch-output"),
				},
			},
		)
		assert.Equal(t, batchInferenceJobLocations{
			inputS3Uri:     "s3://batch-in/records.jsonl",
			outputS3Uri:    "s3://batch-out/results/",
			outputKmsKeyId: "alias/batch-output",
		}, got)
		assert.Equal(t, "batch-in", s3BucketNameFromUri(got.inputS3Uri))
		assert.Equal(t, "batch-out", s3BucketNameFromUri(got.outputS3Uri))
	})

	// Synthetic: output without a key leaves the key empty, so kmsKey is null.
	t.Run("output without key", func(t *testing.T) {
		got := batchInferenceJobLocationsFrom(nil,
			&bedrocktypes.ModelInvocationJobOutputDataConfigMemberS3OutputDataConfig{
				Value: bedrocktypes.ModelInvocationJobS3OutputDataConfig{S3Uri: aws.String("s3://batch-out")},
			},
		)
		assert.Equal(t, batchInferenceJobLocations{outputS3Uri: "s3://batch-out"}, got)
	})

	// Synthetic: an unset union yields no locations.
	t.Run("nil configs", func(t *testing.T) {
		assert.Equal(t, batchInferenceJobLocations{}, batchInferenceJobLocationsFrom(nil, nil))
	})
}

// TestBedrockGuardrailPolicyDictKeys pins the dict keys the guardrail's
// contextualGroundingPolicy and automatedReasoningPolicy doc comments name.
func TestBedrockGuardrailPolicyDictKeys(t *testing.T) {
	// Synthetic: shapes from the GetGuardrail API reference.
	grounding, err := convert.JsonToDict(&bedrocktypes.GuardrailContextualGroundingPolicy{
		Filters: []bedrocktypes.GuardrailContextualGroundingFilter{{
			Type:      bedrocktypes.GuardrailContextualGroundingFilterTypeGrounding,
			Threshold: aws.Float64(0.75),
			Action:    bedrocktypes.GuardrailContextualGroundingActionBlock,
			Enabled:   aws.Bool(true),
		}},
	})
	require.NoError(t, err)
	filters, ok := grounding["Filters"].([]any)
	require.True(t, ok, "Filters key missing: %v", grounding)
	require.Len(t, filters, 1)
	filter := filters[0].(map[string]any)
	assert.Equal(t, "GROUNDING", filter["Type"])
	assert.Equal(t, 0.75, filter["Threshold"])
	assert.Equal(t, "BLOCK", filter["Action"])
	assert.Equal(t, true, filter["Enabled"])

	reasoning, err := convert.JsonToDict(&bedrocktypes.GuardrailAutomatedReasoningPolicy{
		Policies:            []string{"arn:aws:bedrock:us-east-1:123456789012:automated-reasoning-policy/abc"},
		ConfidenceThreshold: aws.Float64(0.9),
	})
	require.NoError(t, err)
	assert.Equal(t, []any{"arn:aws:bedrock:us-east-1:123456789012:automated-reasoning-policy/abc"}, reasoning["Policies"])
	assert.Equal(t, 0.9, reasoning["ConfidenceThreshold"])
}
