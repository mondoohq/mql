// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	bacctypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

func TestCapacityProviderIdFromArn(t *testing.T) {
	tests := []struct {
		name    string
		arn     string
		want    string
		wantErr bool
	}{
		{
			name: "standard capacity provider arn",
			arn:  "arn:aws:bedrock-agentcore:us-east-1:123456789012:capacity-provider/cp-abc123",
			want: "cp-abc123",
		},
		{
			name: "id containing a dash and digits",
			arn:  "arn:aws:bedrock-agentcore:eu-west-1:123456789012:capacity-provider/prod-fleet-01",
			want: "prod-fleet-01",
		},
		{
			name:    "no slash separator",
			arn:     "arn:aws:bedrock-agentcore:us-east-1:123456789012:capacity-provider",
			wantErr: true,
		},
		{
			name:    "trailing slash leaves an empty id",
			arn:     "arn:aws:bedrock-agentcore:us-east-1:123456789012:capacity-provider/",
			wantErr: true,
		},
		{
			name:    "empty arn",
			arn:     "",
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := capacityProviderIdFromArn(test.arn)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestRateConfigsToDicts(t *testing.T) {
	t.Run("nil list yields an empty list, not nil", func(t *testing.T) {
		got := rateConfigsToDicts(nil)
		require.NotNil(t, got)
		assert.Empty(t, got)
	})

	t.Run("renders rate and period", func(t *testing.T) {
		got := rateConfigsToDicts([]bacctypes.RateConfig{
			{Rate: convert.ToPtr(float64(100)), Period: bacctypes.PeriodSecond},
			{Rate: convert.ToPtr(float64(50000)), Period: bacctypes.PeriodMinute},
		})
		require.Len(t, got, 2)
		assert.Equal(t, map[string]any{"rate": float64(100), "period": "second"}, got[0])
		assert.Equal(t, map[string]any{"rate": float64(50000), "period": "minute"}, got[1])
	})

	t.Run("nil rate degrades to zero rather than panicking", func(t *testing.T) {
		got := rateConfigsToDicts([]bacctypes.RateConfig{{Period: bacctypes.PeriodSecond}})
		require.Len(t, got, 1)
		assert.Equal(t, map[string]any{"rate": float64(0), "period": "second"}, got[0])
	})
}

func TestAgentRuntimePlatformVersion(t *testing.T) {
	v := "1.2.3"
	empty := ""
	tests := []struct {
		name   string
		detail *bedrockagentcorecontrol.GetAgentRuntimeOutput
		want   *string
	}{
		{name: "nil response", detail: nil, want: nil},
		{name: "absent value", detail: &bedrockagentcorecontrol.GetAgentRuntimeOutput{}, want: nil},
		{name: "empty value", detail: &bedrockagentcorecontrol.GetAgentRuntimeOutput{PlatformVersion: &empty}, want: nil},
		{name: "reported value", detail: &bedrockagentcorecontrol.GetAgentRuntimeOutput{PlatformVersion: &v}, want: &v},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := agentRuntimePlatformVersion(tc.detail)
			if tc.want == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, "1.2.3", *got)
		})
	}
}

func TestMemoryDeliveryStreamArns(t *testing.T) {
	// Synthetic: no stream delivery configured.
	t.Run("nil", func(t *testing.T) {
		assert.Empty(t, memoryDeliveryStreamArns(nil))
	})

	// Synthetic: two Kinesis destinations, one entry without an ARN, and an
	// unknown union member the SDK may return for a newer destination kind.
	t.Run("kinesis destinations", func(t *testing.T) {
		got := memoryDeliveryStreamArns(&bacctypes.StreamDeliveryResources{
			Resources: []bacctypes.StreamDeliveryResource{
				&bacctypes.StreamDeliveryResourceMemberKinesis{Value: bacctypes.KinesisResource{
					DataStreamArn: convert.ToPtr("arn:aws:kinesis:us-east-1:123456789012:stream/memory-a"),
				}},
				&bacctypes.StreamDeliveryResourceMemberKinesis{Value: bacctypes.KinesisResource{}},
				&bacctypes.UnknownUnionMember{Tag: "eventBridge"},
				&bacctypes.StreamDeliveryResourceMemberKinesis{Value: bacctypes.KinesisResource{
					DataStreamArn: convert.ToPtr("arn:aws:kinesis:us-east-1:123456789012:stream/memory-b"),
				}},
			},
		})
		assert.Equal(t, []string{
			"arn:aws:kinesis:us-east-1:123456789012:stream/memory-a",
			"arn:aws:kinesis:us-east-1:123456789012:stream/memory-b",
		}, got)
	})
}

func TestAgentRuntimeEnvironmentVariableNames(t *testing.T) {
	// Synthetic: no AgentCore runtime existed in the test account; values must never be returned.
	got := agentRuntimeEnvironmentVariableNames(map[string]string{
		"OPENAI_API_KEY": "sk-secret",
		"LOG_LEVEL":      "debug",
	})
	assert.Equal(t, []any{"LOG_LEVEL", "OPENAI_API_KEY"}, got)
	assert.NotContains(t, got, "sk-secret")

	// Synthetic: absent map reads as an empty list, not null.
	assert.Equal(t, []any{}, agentRuntimeEnvironmentVariableNames(nil))
}

func TestAgentRuntimeAllowedPortRanges(t *testing.T) {
	// Synthetic: the AllowedPort union carries either a single port or an inclusive range.
	got := agentRuntimeAllowedPortRanges([]bacctypes.AllowedPort{
		&bacctypes.AllowedPortMemberPort{Value: 8080},
		&bacctypes.AllowedPortMemberPortRange{Value: bacctypes.PortRange{From: aws.Int32(9000), To: aws.Int32(9010)}},
		// Synthetic: a range missing a bound is skipped rather than reported as 0.
		&bacctypes.AllowedPortMemberPortRange{Value: bacctypes.PortRange{From: aws.Int32(10000)}},
		// Synthetic: a union member this SDK does not model is skipped.
		&bacctypes.UnknownUnionMember{Tag: "future"},
	})
	assert.Equal(t, []agentRuntimePortRange{{from: 8080, to: 8080}, {from: 9000, to: 9010}}, got)

	assert.Empty(t, agentRuntimeAllowedPortRanges(nil))
}

func TestAgentRuntimeArtifactOf(t *testing.T) {
	t.Run("container image", func(t *testing.T) {
		// Synthetic: no AgentCore runtime existed in the test account.
		info := agentRuntimeArtifactOf(&bacctypes.AgentRuntimeArtifactMemberContainerConfiguration{
			Value: bacctypes.ContainerConfiguration{ContainerUri: aws.String("123456789012.dkr.ecr.us-east-1.amazonaws.com/agent:v1")},
		})
		require.NotNil(t, info.containerUri)
		assert.Equal(t, "123456789012.dkr.ecr.us-east-1.amazonaws.com/agent:v1", *info.containerUri)
		assert.Nil(t, info.codeRuntime)
		assert.Nil(t, info.codeBucket)
		assert.Nil(t, info.codeS3Prefix)
	})

	t.Run("code package in s3", func(t *testing.T) {
		// Synthetic: no AgentCore runtime existed in the test account.
		info := agentRuntimeArtifactOf(&bacctypes.AgentRuntimeArtifactMemberCodeConfiguration{
			Value: bacctypes.CodeConfiguration{
				Runtime:    bacctypes.AgentManagedRuntimeTypePython312,
				EntryPoint: []string{"main.py"},
				Code: &bacctypes.CodeMemberS3{Value: bacctypes.S3Location{
					Bucket: aws.String("agent-code"),
					Prefix: aws.String("builds/agent.zip"),
				}},
			},
		})
		assert.Nil(t, info.containerUri)
		require.NotNil(t, info.codeRuntime)
		assert.Equal(t, "PYTHON_3_12", *info.codeRuntime)
		assert.Equal(t, []string{"main.py"}, info.codeEntryPoint)
		require.NotNil(t, info.codeBucket)
		assert.Equal(t, "agent-code", *info.codeBucket)
		require.NotNil(t, info.codeS3Prefix)
		assert.Equal(t, "builds/agent.zip", *info.codeS3Prefix)
	})

	t.Run("absent artifact and empty strings read as null", func(t *testing.T) {
		// Synthetic: no artifact, and a container member with an empty URI.
		assert.Equal(t, agentRuntimeArtifactInfo{}, agentRuntimeArtifactOf(nil))
		info := agentRuntimeArtifactOf(&bacctypes.AgentRuntimeArtifactMemberContainerConfiguration{
			Value: bacctypes.ContainerConfiguration{ContainerUri: aws.String("")},
		})
		assert.Nil(t, info.containerUri)
	})
}
