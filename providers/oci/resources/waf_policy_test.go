// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/waf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOciWafActionFields(t *testing.T) {
	t.Run("a blocking action reports its status code and headers", func(t *testing.T) {
		typ, code, headers := ociWafActionFields(waf.ReturnHttpResponseAction{
			Name: new("block"),
			Code: new(403),
			Headers: []waf.ResponseHeader{
				{Name: new("X-Blocked"), Value: new("yes")},
				{Value: new("header without a name is dropped")},
			},
		})
		assert.Equal(t, "RETURN_HTTP_RESPONSE", typ)
		require.NotNil(t, code)
		assert.Equal(t, 403, *code)
		assert.Equal(t, map[string]any{"X-Blocked": "yes"}, headers)
	})

	t.Run("the pointer form of an action is recognized too", func(t *testing.T) {
		typ, code, _ := ociWafActionFields(&waf.ReturnHttpResponseAction{Name: new("block"), Code: new(401)})
		assert.Equal(t, "RETURN_HTTP_RESPONSE", typ)
		require.NotNil(t, code)
		assert.Equal(t, 401, *code)

		typ, _, _ = ociWafActionFields(&waf.AllowAction{Name: new("allow")})
		assert.Equal(t, "ALLOW", typ)
	})

	t.Run("check and allow actions carry no response", func(t *testing.T) {
		typ, code, headers := ociWafActionFields(waf.CheckAction{Name: new("log")})
		assert.Equal(t, "CHECK", typ)
		assert.Nil(t, code)
		assert.Empty(t, headers)

		typ, code, _ = ociWafActionFields(waf.AllowAction{Name: new("allow")})
		assert.Equal(t, "ALLOW", typ)
		assert.Nil(t, code)
	})
}

func TestOciWafPolicyRules(t *testing.T) {
	t.Run("a nil policy has no rules", func(t *testing.T) {
		assert.Empty(t, ociWafPolicyRules(nil))
	})

	t.Run("rules are flattened in module evaluation order", func(t *testing.T) {
		policy := &waf.WebAppFirewallPolicy{
			ResponseProtection: &waf.ResponseProtection{Rules: []waf.ProtectionRule{
				{Name: new("resp-prot"), ActionName: new("block")},
			}},
			RequestProtection: &waf.RequestProtection{Rules: []waf.ProtectionRule{
				{
					Name:                    new("sqli"),
					ActionName:              new("block"),
					IsBodyInspectionEnabled: new(true),
					ProtectionCapabilities: []waf.ProtectionCapability{
						{Key: new("942100"), Version: new(1)},
					},
					ProtectionCapabilitySettings: &waf.ProtectionCapabilitySettings{
						MaxNumberOfArguments: new(255),
						AllowedHttpMethods:   []string{"GET", "POST"},
					},
				},
			}},
			RequestAccessControl: &waf.RequestAccessControl{
				DefaultActionName: new("allow"),
				Rules: []waf.AccessControlRule{
					{Name: new("geo-1"), ActionName: new("block"), Condition: new("i_contains(['CN'], connection.source.geo.countryCode)"), ConditionLanguage: waf.WebAppFirewallPolicyRuleConditionLanguageJmespath},
					{Name: new("geo-2"), ActionName: new("log")},
				},
			},
			RequestRateLimiting: &waf.RequestRateLimiting{Rules: []waf.RequestRateLimitingRule{
				{
					Name:       new("rate"),
					ActionName: new("block"),
					Configurations: []waf.RequestRateLimitingConfiguration{
						{PeriodInSeconds: new(60), RequestsLimit: new(100)},
					},
				},
			}},
			ResponseAccessControl: &waf.ResponseAccessControl{Rules: []waf.AccessControlRule{
				{Name: new("resp-ac"), ActionName: new("log")},
			}},
		}

		rules := ociWafPolicyRules(policy)
		var got [][2]string
		for _, r := range rules {
			got = append(got, [2]string{r.module, r.name})
		}
		assert.Equal(t, [][2]string{
			{"requestAccessControl", "geo-1"},
			{"requestAccessControl", "geo-2"},
			{"requestRateLimiting", "rate"},
			{"requestProtection", "sqli"},
			{"responseAccessControl", "resp-ac"},
			{"responseProtection", "resp-prot"},
		}, got)

		geo := rules[0]
		assert.Equal(t, "ACCESS_CONTROL", geo.ruleType)
		assert.Equal(t, "block", geo.actionName)
		assert.Equal(t, "JMESPATH", geo.conditionLanguage)
		assert.False(t, geo.isProtectionRule)

		rate := rules[2]
		assert.Equal(t, "REQUEST_RATE_LIMITING", rate.ruleType)
		assert.True(t, rate.isRateLimitingRule)
		assert.Len(t, rate.rateLimits, 1)

		sqli := rules[3]
		assert.Equal(t, "PROTECTION", sqli.ruleType)
		assert.True(t, sqli.isProtectionRule)
		require.Len(t, sqli.capabilities, 1)
		assert.Equal(t, "942100", *sqli.capabilities[0].Key)
		require.NotNil(t, sqli.settings)
		assert.Equal(t, 255, *sqli.settings.MaxNumberOfArguments)

		assert.True(t, rules[5].isProtectionRule, "response protection rules are protection rules too")
	})
}

func TestOciWafRateLimits(t *testing.T) {
	got := ociWafRateLimits([]waf.RequestRateLimitingConfiguration{
		{PeriodInSeconds: new(60), RequestsLimit: new(100), ActionDurationInSeconds: new(300)},
		{PeriodInSeconds: new(1), RequestsLimit: new(10)},
	})
	require.Len(t, got, 2)
	assert.Equal(t, map[string]any{
		"periodInSeconds":         int64(60),
		"requestsLimit":           int64(100),
		"actionDurationInSeconds": int64(300),
	}, got[0])
	// An unset duration is not zero seconds: zero would claim the action lifts
	// the moment it is applied.
	assert.Nil(t, got[1].(map[string]any)["actionDurationInSeconds"])
}
