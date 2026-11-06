// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeServiceTierSettings(t *testing.T, payload string) openai.ProjectServiceTierSettings {
	t.Helper()
	var s openai.ProjectServiceTierSettings
	require.NoError(t, json.Unmarshal([]byte(payload), &s))
	return s
}

func TestEnabledServiceTierValues(t *testing.T) {
	// Synthetic: the two shapes of enabled_tiers in the SDK's
	// ProjectServiceTierSettingsEnabledTiersUnion, decoded through the SDK
	// type; no project with service tier settings was available.
	listed := decodeServiceTierSettings(t, `{"object": "project.service_tier_settings", "default": "fast", "enabled_tiers": ["flex", "fast"]}`)
	assert.Equal(t, openai.ProjectServiceTierSettingsDefaultFast, listed.Default)
	tiers, ok, err := enabledServiceTierValues(listed.EnabledTiers.RawJSON())
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, []any{"flex", "fast"}, tiers)

	all := decodeServiceTierSettings(t, `{"default": "standard", "enabled_tiers": "all"}`)
	tiers, ok, err = enabledServiceTierValues(all.EnabledTiers.RawJSON())
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, []any{"all"}, tiers)

	// an empty list allows only standard and must stay distinct from absent
	standardOnly := decodeServiceTierSettings(t, `{"default": "standard", "enabled_tiers": []}`)
	tiers, ok, err = enabledServiceTierValues(standardOnly.EnabledTiers.RawJSON())
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, []any{}, tiers)
}

func TestEnabledServiceTierValuesAbsent(t *testing.T) {
	// Synthetic: a response without enabled_tiers reports null.
	absent := decodeServiceTierSettings(t, `{"default": "standard"}`)
	tiers, ok, err := enabledServiceTierValues(absent.EnabledTiers.RawJSON())
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, tiers)

	_, ok, err = enabledServiceTierValues("null")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestEnabledServiceTierValuesMalformed(t *testing.T) {
	// Synthetic: shapes the API does not document are errors, not guesses.
	_, _, err := enabledServiceTierValues(`[1, 2]`)
	assert.Error(t, err)
	_, _, err = enabledServiceTierValues(`{"tiers": []}`)
	assert.Error(t, err)
}
