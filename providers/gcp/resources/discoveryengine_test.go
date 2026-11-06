// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"cloud.google.com/go/discoveryengine/apiv1/discoveryenginepb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceAccountProjectFromEmail(t *testing.T) {
	// Synthetic: a user-managed service account names its project in the domain.
	assert.Equal(t, "my-project", serviceAccountProjectFromEmail("drive-reader@my-project.iam.gserviceaccount.com"))
	// Synthetic: the Compute Engine default account carries a project number
	// in its local part, not its domain, so it gives no project.
	assert.Empty(t, serviceAccountProjectFromEmail("123456789-compute@developer.gserviceaccount.com"))
	// Synthetic: a Google-managed service agent lives in a Google project.
	assert.Empty(t, serviceAccountProjectFromEmail("service-123@gcp-sa-discoveryengine.iam.gserviceaccount.com"))
	// Synthetic: a user address and an empty value.
	assert.Empty(t, serviceAccountProjectFromEmail("admin@example.com"))
	assert.Empty(t, serviceAccountProjectFromEmail(""))
}

func TestListAcrossDiscoveryEngineLocations(t *testing.T) {
	locations := []string{"global", "us", "eu"}

	// Synthetic: one location refuses, the others still report.
	got, err := listAcrossDiscoveryEngineLocations("engines", locations, func(location string) ([]any, error) {
		if location == "us" {
			return nil, errors.New("unavailable")
		}
		return []any{location}, nil
	})
	assert.NoError(t, err)
	assert.Equal(t, []any{"global", "eu"}, got)

	// Synthetic: every location fails, so the error surfaces.
	_, err = listAcrossDiscoveryEngineLocations("engines", locations, func(location string) ([]any, error) {
		return nil, errors.New("denied " + location)
	})
	assert.EqualError(t, err, "denied global")
}

func TestDiscoveryEngineEnginePostureOf(t *testing.T) {
	t.Run("Gemini Enterprise app with logging and features", func(t *testing.T) {
		// Synthetic: an intranet app that logs prompts, with one feature and
		// one model turned off.
		p := discoveryEngineEnginePostureOf(&discoveryenginepb.Engine{
			AppType:                    discoveryenginepb.Engine_APP_TYPE_INTRANET,
			Features:                   map[string]discoveryenginepb.Engine_FeatureState{"model-selector": discoveryenginepb.Engine_FEATURE_STATE_OFF},
			ModelConfigs:               map[string]discoveryenginepb.Engine_ModelState{"gemini-2.5-pro": discoveryenginepb.Engine_MODEL_DISABLED},
			ObservabilityConfig:        &discoveryenginepb.ObservabilityConfig{ObservabilityEnabled: true, SensitiveLoggingEnabled: true},
			MarketplaceAgentVisibility: discoveryenginepb.Engine_SHOW_ALL_AGENTS,
		})
		assert.Equal(t, "APP_TYPE_INTRANET", p.appType)
		assert.Equal(t, map[string]any{"model-selector": "FEATURE_STATE_OFF"}, p.features)
		assert.Equal(t, map[string]any{"gemini-2.5-pro": "MODEL_DISABLED"}, p.modelConfigs)
		require.NotNil(t, p.observabilityEnabled)
		assert.True(t, *p.observabilityEnabled)
		require.NotNil(t, p.sensitiveLoggingEnabled)
		assert.True(t, *p.sensitiveLoggingEnabled)
		assert.Equal(t, "SHOW_ALL_AGENTS", p.marketplaceAgentVisibility)
	})

	t.Run("observability configured off", func(t *testing.T) {
		// Synthetic: the config is present with both switches off.
		p := discoveryEngineEnginePostureOf(&discoveryenginepb.Engine{ObservabilityConfig: &discoveryenginepb.ObservabilityConfig{}})
		require.NotNil(t, p.sensitiveLoggingEnabled)
		assert.False(t, *p.sensitiveLoggingEnabled)
	})

	t.Run("search app with nothing set", func(t *testing.T) {
		// Synthetic: a plain search engine; unset enums are empty, no
		// observability config is null.
		p := discoveryEngineEnginePostureOf(&discoveryenginepb.Engine{})
		assert.Empty(t, p.appType)
		assert.Empty(t, p.marketplaceAgentVisibility)
		assert.Nil(t, p.observabilityEnabled)
		assert.Nil(t, p.sensitiveLoggingEnabled)
		assert.Equal(t, map[string]any{}, p.features)
	})
}

func TestDiscoveryEngineAssistantPolicyOf(t *testing.T) {
	t.Run("assistant with Model Armor, banned phrases, SDP and tools", func(t *testing.T) {
		// Synthetic: a fully configured default assistant.
		p := discoveryEngineAssistantPolicyOf(&discoveryenginepb.Assistant{
			WebGroundingType: discoveryenginepb.Assistant_WEB_GROUNDING_TYPE_GOOGLE_SEARCH,
			EnabledTools: map[string]*discoveryenginepb.Assistant_ToolList{
				"projects/p/locations/global/collections/jira/dataConnector":  {ToolInfo: []*discoveryenginepb.Assistant_ToolInfo{{ToolName: "create_issue"}}},
				"projects/p/locations/global/collections/gmail/dataConnector": {ToolInfo: []*discoveryenginepb.Assistant_ToolInfo{{ToolName: "send_email"}, {ToolName: "draft_email"}}},
			},
			CustomerPolicy: &discoveryenginepb.Assistant_CustomerPolicy{
				BannedPhrases: []*discoveryenginepb.Assistant_CustomerPolicy_BannedPhrase{{Phrase: "project falcon"}, {Phrase: "salary"}},
				ModelArmorConfig: &discoveryenginepb.Assistant_CustomerPolicy_ModelArmorConfig{
					UserPromptTemplate: "projects/p/locations/us/templates/prompt",
					ResponseTemplate:   "projects/p/locations/us/templates/response",
					FailureMode:        discoveryenginepb.Assistant_CustomerPolicy_ModelArmorConfig_FAIL_OPEN,
				},
				DataProtectionPolicy: &discoveryenginepb.DataProtectionPolicy{
					SensitiveDataProtectionPolicy: &discoveryenginepb.DataProtectionPolicy_SensitiveDataProtectionPolicy{Policy: "projects/p/locations/global/contentPolicies/cp"},
				},
			},
		})
		assert.Equal(t, "projects/p/locations/us/templates/prompt", p.promptTemplate)
		assert.Equal(t, "projects/p/locations/us/templates/response", p.responseTemplate)
		assert.Equal(t, "FAIL_OPEN", p.failureMode)
		assert.Equal(t, []string{"project falcon", "salary"}, p.bannedPhrases)
		assert.Equal(t, "projects/p/locations/global/contentPolicies/cp", p.contentPolicy)
		assert.Equal(t, "WEB_GROUNDING_TYPE_GOOGLE_SEARCH", p.webGroundingType)
		// Connectors sorted by name, tools in API order within each.
		assert.Equal(t, []string{"send_email", "draft_email", "create_issue"}, p.enabledTools)
	})

	t.Run("assistant with no policy", func(t *testing.T) {
		// Synthetic: nothing configured.
		p := discoveryEngineAssistantPolicyOf(&discoveryenginepb.Assistant{})
		assert.Empty(t, p.promptTemplate)
		assert.Empty(t, p.failureMode)
		assert.Empty(t, p.webGroundingType)
		assert.Equal(t, []string{}, p.bannedPhrases)
		assert.Equal(t, []string{}, p.enabledTools)
	})
}
