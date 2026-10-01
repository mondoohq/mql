// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	kjson "github.com/microsoft/kiota-serialization-json-go"
	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAutopilotOobeToDict_Nil(t *testing.T) {
	assert.Nil(t, autopilotOobeToDict(nil))
}

func TestAutopilotOobeToDict_AllFields(t *testing.T) {
	s := betamodels.NewOutOfBoxExperienceSettings()
	s.SetHidePrivacySettings(ptr(true))
	s.SetHideEULA(ptr(false))
	s.SetSkipKeyboardSelectionPage(ptr(true))
	s.SetHideEscapeLink(ptr(true))
	userType := betamodels.STANDARD_WINDOWSUSERTYPE
	s.SetUserType(&userType)
	deviceUsage := betamodels.SHARED_WINDOWSDEVICEUSAGETYPE
	s.SetDeviceUsageType(&deviceUsage)

	got := autopilotOobeToDict(s)
	assert.Equal(t, map[string]any{
		"hidePrivacySettings":       true,
		"hideEULA":                  false,
		"skipKeyboardSelectionPage": true,
		"hideEscapeLink":            true,
		"userType":                  "standard",
		"deviceUsageType":           "shared",
	}, got)
}

func decodeAutopilotProfile(t *testing.T, body string) betamodels.WindowsAutopilotDeploymentProfileable {
	node, err := kjson.NewJsonParseNode([]byte(body))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(betamodels.CreateWindowsAutopilotDeploymentProfileFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(betamodels.WindowsAutopilotDeploymentProfileable)
}

// Microsoft deprecated language, enableWhiteGlove, extractHardwareHash and
// outOfBoxExperienceSettings in May 2024. A profile that only carries the
// replacements (locale, preprovisioningAllowed, hardwareHashExtractionEnabled,
// outOfBoxExperienceSetting) must still populate every existing field.
func TestAutopilotProfileArgs_CurrentPropertiesOnly(t *testing.T) {
	p := decodeAutopilotProfile(t, `{
		"@odata.type": "#microsoft.graph.azureADWindowsAutopilotDeploymentProfile",
		"id": "profile-1",
		"displayName": "Corp laptops",
		"locale": "de-DE",
		"preprovisioningAllowed": true,
		"hardwareHashExtractionEnabled": true,
		"outOfBoxExperienceSetting": {
			"privacySettingsHidden": true,
			"eulaHidden": true,
			"userType": "standard",
			"keyboardSelectionPageSkipped": true,
			"deviceUsageType": "singleUser",
			"escapeLinkHidden": false
		}
	}`)
	args := autopilotProfileArgs(p)

	assert.Equal(t, "de-DE", args["language"].Value)
	assert.Equal(t, "de-DE", args["locale"].Value)
	assert.Equal(t, true, args["enableWhiteGlove"].Value)
	assert.Equal(t, true, args["extractHardwareHash"].Value)
	assert.Equal(t, "azureADWindowsAutopilotDeploymentProfile", args["deploymentProfileType"].Value)
	assert.Equal(t, map[string]any{
		"hidePrivacySettings":       true,
		"hideEULA":                  true,
		"skipKeyboardSelectionPage": true,
		"hideEscapeLink":            false,
		"userType":                  "standard",
		"deviceUsageType":           "singleUser",
	}, args["outOfBoxExperienceSettings"].Value)

	result := args["outOfBoxExperienceSettings"].Result()
	assert.Empty(t, result.Error)
}

// Older profiles that only carry the deprecated properties keep working, and
// when both are present the current property wins.
func TestAutopilotProfileArgs_DeprecatedFallbackAndPrecedence(t *testing.T) {
	legacy := decodeAutopilotProfile(t, `{
		"id": "profile-2",
		"language": "en-US",
		"enableWhiteGlove": true,
		"extractHardwareHash": false,
		"outOfBoxExperienceSettings": {"hideEULA": true, "userType": "administrator"}
	}`)
	args := autopilotProfileArgs(legacy)
	assert.Equal(t, "en-US", args["language"].Value)
	assert.Equal(t, "en-US", args["locale"].Value)
	assert.Equal(t, true, args["enableWhiteGlove"].Value)
	assert.Equal(t, false, args["extractHardwareHash"].Value)
	assert.Equal(t, map[string]any{"hideEULA": true, "userType": "administrator"}, args["outOfBoxExperienceSettings"].Value)

	both := decodeAutopilotProfile(t, `{
		"id": "profile-3",
		"language": "en-US",
		"locale": "fr-FR",
		"enableWhiteGlove": true,
		"preprovisioningAllowed": false,
		"outOfBoxExperienceSettings": {"hideEULA": false, "hidePrivacySettings": true},
		"outOfBoxExperienceSetting": {"eulaHidden": true}
	}`)
	args = autopilotProfileArgs(both)
	assert.Equal(t, "fr-FR", args["language"].Value)
	assert.Equal(t, false, args["enableWhiteGlove"].Value)
	assert.Equal(t, map[string]any{"hideEULA": true, "hidePrivacySettings": true}, args["outOfBoxExperienceSettings"].Value,
		"the current object wins per key; keys it lacks fall back to the deprecated one")
}

func TestAutopilotProfileArgs_AbsentIsNull(t *testing.T) {
	args := autopilotProfileArgs(decodeAutopilotProfile(t, `{"id": "profile-4"}`))
	assert.Nil(t, args["language"].Value)
	assert.Nil(t, args["enableWhiteGlove"].Value)
	assert.Nil(t, args["extractHardwareHash"].Value)
}

func TestAutopilotOobeToDict_OmitsNilFields(t *testing.T) {
	s := betamodels.NewOutOfBoxExperienceSettings()
	s.SetHideEULA(ptr(true))

	got := autopilotOobeToDict(s)
	assert.Equal(t, map[string]any{"hideEULA": true}, got)
	assert.NotContains(t, got, "hidePrivacySettings")
	assert.NotContains(t, got, "userType")
}
