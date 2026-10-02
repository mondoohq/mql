// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	betadm "github.com/microsoftgraph/msgraph-beta-sdk-go/devicemanagement"
	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/ms365/connection"
)

func (m *mqlMicrosoftDevicemanagementWindowsAutopilotDeploymentProfile) id() (string, error) {
	return m.Id.Data, nil
}

func (a *mqlMicrosoftDevicemanagement) windowsAutopilotDeploymentProfiles() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	// $expand=assignedDevices so the per-profile device count below is non-zero.
	reqConfig := &betadm.WindowsAutopilotDeploymentProfilesRequestBuilderGetRequestConfiguration{
		QueryParameters: &betadm.WindowsAutopilotDeploymentProfilesRequestBuilderGetQueryParameters{
			Expand: []string{"assignedDevices"},
		},
	}
	resp, err := graphClient.DeviceManagement().WindowsAutopilotDeploymentProfiles().Get(ctx, reqConfig)
	if err != nil {
		return nil, transformError(err)
	}
	profiles, err := iterate[betamodels.WindowsAutopilotDeploymentProfileable](ctx, resp, graphClient.GetAdapter(), betamodels.CreateWindowsAutopilotDeploymentProfileCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, profile := range profiles {
		r, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement.windowsAutopilotDeploymentProfile", autopilotProfileArgs(profile))
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func autopilotProfileArgs(profile betamodels.WindowsAutopilotDeploymentProfileable) map[string]*llx.RawData {
	profileType := ""
	if v := profile.GetOdataType(); v != nil {
		profileType = trimOdataType(*v)
	}
	assignedDeviceCount := int64(0)
	if devices := profile.GetAssignedDevices(); devices != nil {
		assignedDeviceCount = int64(len(devices))
	}
	locale := firstNonNil(profile.GetLocale(), profile.GetLanguage())
	return map[string]*llx.RawData{
		"__id":                       llx.StringDataPtr(profile.GetId()),
		"id":                         llx.StringDataPtr(profile.GetId()),
		"displayName":                llx.StringDataPtr(profile.GetDisplayName()),
		"description":                llx.StringDataPtr(profile.GetDescription()),
		"language":                   llx.StringDataPtr(locale),
		"locale":                     llx.StringDataPtr(locale),
		"deviceNameTemplate":         llx.StringDataPtr(profile.GetDeviceNameTemplate()),
		"deploymentProfileType":      llx.StringData(profileType),
		"extractHardwareHash":        llx.BoolDataPtr(firstNonNil(profile.GetHardwareHashExtractionEnabled(), profile.GetExtractHardwareHash())),
		"enableWhiteGlove":           llx.BoolDataPtr(firstNonNil(profile.GetPreprovisioningAllowed(), profile.GetEnableWhiteGlove())),
		"outOfBoxExperienceSettings": llx.DictData(autopilotProfileOobe(profile)),
		"assignedDeviceCount":        llx.IntData(assignedDeviceCount),
		"createdDateTime":            graphTimeData(profile.GetCreatedDateTime()),
		"lastModifiedDateTime":       graphTimeData(profile.GetLastModifiedDateTime()),
	}
}

// firstNonNil returns the first non-nil pointer. Autopilot profiles carry
// both the current property and the one Microsoft deprecated in May 2024
// (locale over language, preprovisioningAllowed over enableWhiteGlove,
// hardwareHashExtractionEnabled over extractHardwareHash); newer profiles
// may only populate the current one.
func firstNonNil[T any](vals ...*T) *T {
	for _, v := range vals {
		if v != nil {
			return v
		}
	}
	return nil
}

// autopilotProfileOobe builds the out-of-box experience dict from the current
// outOfBoxExperienceSetting property, falling back per key to the deprecated
// outOfBoxExperienceSettings. Every documented key has an equivalent in both.
func autopilotProfileOobe(p betamodels.WindowsAutopilotDeploymentProfileable) map[string]any {
	legacy := autopilotOobeToDict(p.GetOutOfBoxExperienceSettings())
	current := autopilotOobeSettingToDict(p.GetOutOfBoxExperienceSetting())
	if current == nil {
		return legacy
	}
	for k, v := range legacy {
		if _, ok := current[k]; !ok {
			current[k] = v
		}
	}
	return current
}

// autopilotOobeSettingToDict maps the current outOfBoxExperienceSetting onto
// the keys of the deprecated outOfBoxExperienceSettings shape.
func autopilotOobeSettingToDict(s betamodels.OutOfBoxExperienceSettingable) map[string]any {
	if s == nil {
		return nil
	}
	out := map[string]any{}
	if v := s.GetPrivacySettingsHidden(); v != nil {
		out["hidePrivacySettings"] = *v
	}
	if v := s.GetEulaHidden(); v != nil {
		out["hideEULA"] = *v
	}
	if v := s.GetKeyboardSelectionPageSkipped(); v != nil {
		out["skipKeyboardSelectionPage"] = *v
	}
	if v := s.GetEscapeLinkHidden(); v != nil {
		out["hideEscapeLink"] = *v
	}
	if v := s.GetUserType(); v != nil {
		out["userType"] = v.String()
	}
	if v := s.GetDeviceUsageType(); v != nil {
		out["deviceUsageType"] = v.String()
	}
	return out
}

func autopilotOobeToDict(s betamodels.OutOfBoxExperienceSettingsable) map[string]any {
	if s == nil {
		return nil
	}
	out := map[string]any{}
	if v := s.GetHidePrivacySettings(); v != nil {
		out["hidePrivacySettings"] = *v
	}
	if v := s.GetHideEULA(); v != nil {
		out["hideEULA"] = *v
	}
	if v := s.GetSkipKeyboardSelectionPage(); v != nil {
		out["skipKeyboardSelectionPage"] = *v
	}
	if v := s.GetHideEscapeLink(); v != nil {
		out["hideEscapeLink"] = *v
	}
	if v := s.GetUserType(); v != nil {
		out["userType"] = v.String()
	}
	if v := s.GetDeviceUsageType(); v != nil {
		out["deviceUsageType"] = v.String()
	}
	return out
}
