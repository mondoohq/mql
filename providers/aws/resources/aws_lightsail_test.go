// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	lightsail_types "github.com/aws/aws-sdk-go-v2/service/lightsail/types"
	"github.com/stretchr/testify/assert"
)

// The account used for verification had no Lightsail instances or
// distributions, so every case here is synthetic, shaped after the
// GetInstances and GetDistributions API reference.

func TestLightsailHealthStatus(t *testing.T) {
	// Synthetic: GetInstances without IncludeHealthStatus omits the checks.
	status, since := lightsailHealthStatus(nil)
	assert.Nil(t, status.Value)
	assert.Nil(t, since.Value)

	// Synthetic: a passing reachability check carries no impairedSince.
	status, since = lightsailHealthStatus(&lightsail_types.InstanceHealthStatus{
		Status: lightsail_types.InstanceHealthStatusValueOk,
		Details: []lightsail_types.InstanceHealthStatusDetail{{
			Name:   lightsail_types.InstanceHealthStatusDetailNameReachability,
			Status: lightsail_types.InstanceHealthStatusDetailValuePassed,
		}},
	})
	assert.Equal(t, "ok", status.Value)
	assert.Nil(t, since.Value)

	// Synthetic: an impaired check reports the earliest failure time.
	early := time.Date(2026, 10, 29, 8, 0, 0, 0, time.UTC)
	late := early.Add(time.Hour)
	status, since = lightsailHealthStatus(&lightsail_types.InstanceHealthStatus{
		Status: lightsail_types.InstanceHealthStatusValueImpaired,
		Details: []lightsail_types.InstanceHealthStatusDetail{
			{Status: lightsail_types.InstanceHealthStatusDetailValueFailed, ImpairedSince: &late},
			{Status: lightsail_types.InstanceHealthStatusDetailValueFailed, ImpairedSince: &early},
		},
	})
	assert.Equal(t, "impaired", status.Value)
	assert.Equal(t, &early, since.Value)
}

func TestLightsailWafArgs(t *testing.T) {
	// Synthetic: a distribution without a WAF configuration.
	enabled, groups := lightsailWafArgs(nil)
	assert.Nil(t, enabled.Value)
	assert.Nil(t, groups.Value)

	// Synthetic: WAF on with two managed rule groups, one with bot control settings.
	enabled, groups = lightsailWafArgs(&lightsail_types.WafConfig{
		IsWafEnabled: aws.Bool(true),
		WafRules: []lightsail_types.WafRule{
			{Name: aws.String("AWSManagedRulesCommonRuleSet")},
			{
				Name:             aws.String("AWSManagedRulesBotControlRuleSet"),
				BotControlConfig: &lightsail_types.WafBotControlConfig{InspectionLevel: lightsail_types.WafInspectionLevelEnumCommon},
			},
		},
	})
	assert.Equal(t, true, enabled.Value)
	assert.Equal(t, []any{"AWSManagedRulesCommonRuleSet", "AWSManagedRulesBotControlRuleSet"}, groups.Value)

	// Synthetic: WAF configuration present but switched off, with no rules.
	enabled, groups = lightsailWafArgs(&lightsail_types.WafConfig{IsWafEnabled: aws.Bool(false)})
	assert.Equal(t, false, enabled.Value)
	assert.Equal(t, []any{}, groups.Value)
}
