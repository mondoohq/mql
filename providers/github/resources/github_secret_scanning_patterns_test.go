// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/google/go-github/v93/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// Synthetic: pattern configuration entries shaped like GitHub's documented
// response; no target showed these.
func TestPatternOverrideArgs(t *testing.T) {
	var configs github.SecretScanningPatternConfigs
	require.NoError(t, json.Unmarshal([]byte(`{
		"pattern_config_version": "v1",
		"provider_pattern_overrides": [
			{"token_type": "GITHUB_PAT", "slug": "github_pat", "display_name": "GitHub PAT",
			 "alert_total": 0, "false_positive_rate": 3, "bypass_rate": 12,
			 "default_setting": "enabled", "setting": "disabled"}
		],
		"custom_pattern_overrides": [
			{"token_type": "cp_1", "custom_pattern_version": "abc", "slug": "internal_key", "display_name": "Internal key"}
		]
	}`), &configs))

	provider := patternOverrideArgs("o", patternKindProvider, configs.ProviderPatternOverrides[0])
	assert.Equal(t, "disabled", provider["setting"].Value)
	assert.Equal(t, int64(0), provider["alertTotal"].Value, "a reported zero is a zero")
	assert.Equal(t, int64(12), provider["bypassRate"].Value)
	assert.Equal(t, llx.NilData, provider["falsePositives"], "an absent statistic is null, not zero")
	assert.Equal(t, llx.NilData, provider["customPatternVersion"])

	custom := patternOverrideArgs("o", patternKindCustom, configs.CustomPatternOverrides[0])
	assert.Equal(t, "abc", custom["customPatternVersion"].Value)
	assert.Equal(t, llx.NilData, custom["alertTotal"])
	assert.NotEqual(t, provider["__id"].Value, custom["__id"].Value)
}

// Synthetic: the same pattern id in two scopes; no target showed this.
func TestSecretScanningCustomPatternIDIsScoped(t *testing.T) {
	org := secretScanningCustomPatternID(scopeOrganization, "o", "", 5)
	repo := secretScanningCustomPatternID(scopeRepository, "o", "r", 5)
	other := secretScanningCustomPatternID(scopeRepository, "o", "s", 5)
	assert.NotEqual(t, org, repo)
	assert.NotEqual(t, repo, other)
}
