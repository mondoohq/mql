// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestWafTemplateEnabled(t *testing.T) {
	tests := []struct {
		name     string
		status   *int32
		expected bool
	}{
		{"enabled", tea.Int32(1), true},
		{"disabled", tea.Int32(0), false},
		// an absent switch must read as off: reporting it on would claim
		// protection that was never confirmed
		{"absent", nil, false},
		{"unknown value", tea.Int32(7), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, wafTemplateEnabled(test.status))
			assert.Equal(t, test.expected, wafRuleEnabled(test.status))
		})
	}
}

func TestParseWafRuleConfig(t *testing.T) {
	t.Run("object", func(t *testing.T) {
		cfg := parseWafRuleConfig(new(`{"action":"block","ratio":10}`))
		obj, ok := cfg.(map[string]any)
		require.True(t, ok, "a JSON object config decodes to a map")
		assert.Equal(t, "block", obj["action"])
	})

	t.Run("array", func(t *testing.T) {
		cfg := parseWafRuleConfig(new(`["203.0.113.0/24"]`))
		entries, ok := cfg.([]any)
		require.True(t, ok, "a JSON array config decodes to a slice")
		assert.Equal(t, []any{"203.0.113.0/24"}, entries)
	})

	t.Run("blank and unparseable stay null", func(t *testing.T) {
		// null rather than an empty object: an empty object would read as
		// "the rule matches nothing", which is a different claim
		assert.Nil(t, parseWafRuleConfig(nil))
		assert.Nil(t, parseWafRuleConfig(new("")))
		assert.Nil(t, parseWafRuleConfig(new("   ")))
		assert.Nil(t, parseWafRuleConfig(new("not json")))
	})
}

// wafTestTemplate builds a template resource with only the members
// wafEnabledDefenseScenes reads.
func wafTestTemplate(scene string, enabled bool) *mqlAlicloudWafDefenseTemplate {
	return &mqlAlicloudWafDefenseTemplate{
		DefenseScene: plugin.TValue[string]{Data: scene, State: plugin.StateIsSet},
		Enabled:      plugin.TValue[bool]{Data: enabled, State: plugin.StateIsSet},
	}
}

func TestWafEnabledDefenseScenes(t *testing.T) {
	tests := []struct {
		name      string
		templates []any
		expected  []any
	}{
		{
			name:      "no templates bound",
			templates: []any{},
			expected:  []any{},
		},
		{
			name: "every template switched off",
			templates: []any{
				wafTestTemplate("waf_group", false),
				wafTestTemplate("cc", false),
			},
			// the onboarded-but-undefended case the finding is about
			expected: []any{},
		},
		{
			name: "only the enabled scenes are reported, sorted",
			templates: []any{
				wafTestTemplate("waf_group", true),
				wafTestTemplate("cc", false),
				wafTestTemplate("custom_acl", true),
			},
			expected: []any{"custom_acl", "waf_group"},
		},
		{
			name: "duplicate scenes collapse",
			templates: []any{
				wafTestTemplate("custom_acl", true),
				wafTestTemplate("custom_acl", true),
			},
			expected: []any{"custom_acl"},
		},
		{
			name: "blank scene is dropped",
			templates: []any{
				wafTestTemplate("", true),
				wafTestTemplate("dlp", true),
			},
			expected: []any{"dlp"},
		},
		{
			name:      "non-template entries are ignored",
			templates: []any{"not a template", nil},
			expected:  []any{},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, wafEnabledDefenseScenes(test.templates))
		})
	}
}

func TestWafTemplateRuleQuery(t *testing.T) {
	query, err := wafTemplateRuleQuery(56477)
	require.NoError(t, err)
	assert.JSONEq(t, `{"templateId":56477}`, query)
}
