// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

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
