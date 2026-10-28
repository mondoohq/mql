// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestCombineRestrictions(t *testing.T) {
	t.Run("no payloads leaves every key unset", func(t *testing.T) {
		// Synthetic: a Mac with no Restrictions payload; no target showed this.
		assert.Empty(t, combineRestrictions(nil))
	})

	t.Run("a payload without Apple Intelligence keys sets nothing", func(t *testing.T) {
		// Synthetic: a Restrictions payload carrying only unrelated keys; no target showed this.
		got := combineRestrictions([]map[string]any{{"allowAirDrop": false, "allowCamera": true}})
		assert.Empty(t, got)
	})

	t.Run("keys are read from one payload", func(t *testing.T) {
		// Synthetic: key names from Apple's com.apple.applicationaccess schema; no target showed this.
		got := combineRestrictions([]map[string]any{{
			"allowWritingTools":                           false,
			"allowGenmoji":                                false,
			"allowImagePlayground":                        true,
			"allowExternalIntelligenceIntegrations":       false,
			"allowExternalIntelligenceIntegrationsSignIn": true,
			"allowMailSummary":                            false,
			"allowMailSmartReplies":                       true,
			"allowNotesTranscription":                     false,
			"allowNotesTranscriptionSummary":              true,
			"allowSafariSummary":                          false,
			"allowAppleIntelligenceReport":                true,
		}})
		assert.Equal(t, map[string]bool{
			"allowWritingTools":                           false,
			"allowGenmoji":                                false,
			"allowImagePlayground":                        true,
			"allowExternalIntelligenceIntegrations":       false,
			"allowExternalIntelligenceIntegrationsSignIn": true,
			"allowMailSummary":                            false,
			"allowMailSmartReplies":                       true,
			"allowNotesTranscription":                     false,
			"allowNotesTranscriptionSummary":              true,
			"allowSafariSummary":                          false,
			"allowAppleIntelligenceReport":                true,
		}, got)
	})

	t.Run("most restrictive value wins across payloads, in either order", func(t *testing.T) {
		// Synthetic: two profiles disagreeing; no target showed this.
		allow := map[string]any{"allowWritingTools": true, "allowGenmoji": true}
		deny := map[string]any{"allowWritingTools": false}
		for _, order := range [][]map[string]any{{allow, deny}, {deny, allow}} {
			got := combineRestrictions(order)
			assert.Equal(t, map[string]bool{"allowWritingTools": false, "allowGenmoji": true}, got)
		}
	})

	t.Run("string spellings are accepted, other types ignored", func(t *testing.T) {
		// Synthetic: string and integer values; no target showed this.
		got := combineRestrictions([]map[string]any{{
			"allowWritingTools":    "false",
			"allowGenmoji":         "TRUE",
			"allowImagePlayground": int64(0),
		}})
		assert.Equal(t, map[string]bool{"allowWritingTools": false, "allowGenmoji": true}, got)
	})
}

func TestSetsAppleIntelligenceRestriction(t *testing.T) {
	// Synthetic: payload contents; no target showed this.
	assert.False(t, setsAppleIntelligenceRestriction(map[string]any{"allowAirDrop": false}))
	assert.True(t, setsAppleIntelligenceRestriction(map[string]any{"allowSafariSummary": true}))
}

func TestRestrictionField(t *testing.T) {
	// Synthetic: not set is null, a set key keeps its value; no target showed this.
	values := map[string]bool{"allowGenmoji": false}
	unset := restrictionField(values, "allowWritingTools")
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, unset.State)
	set := restrictionField(values, "allowGenmoji")
	assert.Equal(t, plugin.StateIsSet, set.State)
	assert.False(t, set.Data)
}
