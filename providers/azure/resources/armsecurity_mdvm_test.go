// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// documentedServerVASettingsBody is shaped like the response ARM returns, taken
// from the SDK's own recorded example for
// ServerVulnerabilityAssessmentsSettingsClient (armsecurity@v0.15.0,
// servervulnerabilityassessmentssettings_client_example_test.go).
//
// The casing is the whole point of the fixture: "kind" carries the capitalized
// discriminator, "name" the lower-cased resource name.
const documentedServerVASettingsBody = `{
  "value": [
    {
      "properties": { "selectedProvider": "MdeTvm" },
      "kind": "AzureServersSetting",
      "name": "azureServersSetting",
      "type": "Microsoft.Security/serverVulnerabilityAssessmentsSettings",
      "id": "/subscriptions/0000/providers/Microsoft.Security/serverVulnerabilityAssessmentsSettings/azureServersSetting"
    }
  ]
}`

// TestMdvmDetectedInDocumentedResponse pins the bug this function exists to
// prevent: the match used to compare the resource NAME against the KIND value
// ("AzureServersSetting"), which Go compares case-sensitively, so the branch was
// dead. A subscription using Microsoft Defender Vulnerability Management -- the
// only provider since the Qualys scanner was retired -- reported no
// vulnerability management tool at all.
func TestMdvmDetectedInDocumentedResponse(t *testing.T) {
	var list ServerVulnerabilityAssessmentsSettingsList
	require.NoError(t, json.Unmarshal([]byte(documentedServerVASettingsBody), &list))
	require.Len(t, list.Settings, 1)

	// The decode itself is worth asserting: these two fields differ only by a
	// leading capital, so a struct-tag slip is invisible without it.
	assert.Equal(t, "AzureServersSetting", list.Settings[0].Kind)
	assert.Equal(t, "azureServersSetting", list.Settings[0].Name)
	assert.Equal(t, "MdeTvm", list.Settings[0].Properties.SelectedProvider)

	assert.True(t, mdvmVulnerabilityAssessmentEnabled(list.Settings))
}

func TestMdvmVulnerabilityAssessmentEnabled(t *testing.T) {
	setting := func(provider, kind, name string) ServerVulnerabilityAssessmentsSettings {
		s := ServerVulnerabilityAssessmentsSettings{Kind: kind, Name: name}
		s.Properties.SelectedProvider = provider
		return s
	}

	t.Run("matches on the kind", func(t *testing.T) {
		assert.True(t, mdvmVulnerabilityAssessmentEnabled([]ServerVulnerabilityAssessmentsSettings{
			setting("MdeTvm", "AzureServersSetting", ""),
		}))
	})

	t.Run("matches on the name", func(t *testing.T) {
		assert.True(t, mdvmVulnerabilityAssessmentEnabled([]ServerVulnerabilityAssessmentsSettings{
			setting("MdeTvm", "", "azureServersSetting"),
		}))
	})

	t.Run("matches either casing on either field", func(t *testing.T) {
		// The hand-rolled call is pinned to an older api-version, so neither
		// spelling can be assumed away.
		for _, s := range []ServerVulnerabilityAssessmentsSettings{
			setting("MdeTvm", "azureServersSetting", ""),
			setting("MdeTvm", "", "AzureServersSetting"),
			setting("mdetvm", "AzureServersSetting", ""),
		} {
			assert.True(t, mdvmVulnerabilityAssessmentEnabled([]ServerVulnerabilityAssessmentsSettings{s}))
		}
	})

	t.Run("a different provider does not count", func(t *testing.T) {
		// Qualys is the retired provider and has its own detection path; it must
		// not be reported as Defender Vulnerability Management.
		assert.False(t, mdvmVulnerabilityAssessmentEnabled([]ServerVulnerabilityAssessmentsSettings{
			setting("Qualys", "AzureServersSetting", "azureServersSetting"),
		}))
	})

	t.Run("a different setting does not count", func(t *testing.T) {
		assert.False(t, mdvmVulnerabilityAssessmentEnabled([]ServerVulnerabilityAssessmentsSettings{
			setting("MdeTvm", "SomeOtherSetting", "someOtherSetting"),
		}))
	})

	t.Run("no settings", func(t *testing.T) {
		assert.False(t, mdvmVulnerabilityAssessmentEnabled(nil))
		assert.False(t, mdvmVulnerabilityAssessmentEnabled([]ServerVulnerabilityAssessmentsSettings{}))
	})

	t.Run("finds a match past a non-matching entry", func(t *testing.T) {
		assert.True(t, mdvmVulnerabilityAssessmentEnabled([]ServerVulnerabilityAssessmentsSettings{
			setting("Qualys", "SomeOtherSetting", "someOtherSetting"),
			setting("MdeTvm", "AzureServersSetting", "azureServersSetting"),
		}))
	})
}
