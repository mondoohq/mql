// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// windowsUpdateRings lists the Windows Update for Business rings. They are
// device configurations of type windowsUpdateForBusinessConfiguration, so the
// device-configuration collection is filtered to that type.
// requires DeviceManagementConfiguration.Read.All permission
func (a *mqlMicrosoftDevicemanagement) windowsUpdateRings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().DeviceConfigurations().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	configurations, err := iterate[models.DeviceConfigurationable](ctx, resp, graphClient.GetAdapter(), models.CreateDeviceConfigurationCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, c := range configurations {
		ring, ok := c.(models.WindowsUpdateForBusinessConfigurationable)
		if !ok {
			continue
		}
		mqlRing, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement.windowsUpdateRing",
			map[string]*llx.RawData{
				"__id":                               llx.StringDataPtr(ring.GetId()),
				"id":                                 llx.StringDataPtr(ring.GetId()),
				"displayName":                        llx.StringDataPtr(ring.GetDisplayName()),
				"description":                        llx.StringDataPtr(ring.GetDescription()),
				"automaticUpdateMode":                llx.StringDataPtr(enumPtrString(ring.GetAutomaticUpdateMode())),
				"businessReadyUpdatesOnly":           llx.StringDataPtr(enumPtrString(ring.GetBusinessReadyUpdatesOnly())),
				"featureUpdatesDeferralPeriodInDays": llx.IntDataPtr(ring.GetFeatureUpdatesDeferralPeriodInDays()),
				"qualityUpdatesDeferralPeriodInDays": llx.IntDataPtr(ring.GetQualityUpdatesDeferralPeriodInDays()),
				"featureUpdatesPaused":               llx.BoolDataPtr(ring.GetFeatureUpdatesPaused()),
				"qualityUpdatesPaused":               llx.BoolDataPtr(ring.GetQualityUpdatesPaused()),
				"deadlineForFeatureUpdatesInDays":    llx.IntDataPtr(ring.GetDeadlineForFeatureUpdatesInDays()),
				"deadlineForQualityUpdatesInDays":    llx.IntDataPtr(ring.GetDeadlineForQualityUpdatesInDays()),
				"deadlineGracePeriodInDays":          llx.IntDataPtr(ring.GetDeadlineGracePeriodInDays()),
				"postponeRebootUntilAfterDeadline":   llx.BoolDataPtr(ring.GetPostponeRebootUntilAfterDeadline()),
				"driversExcluded":                    llx.BoolDataPtr(ring.GetDriversExcluded()),
				"prereleaseFeatures":                 llx.StringDataPtr(enumPtrString(ring.GetPrereleaseFeatures())),
				"userPauseAccess":                    llx.StringDataPtr(enumPtrString(ring.GetUserPauseAccess())),
				"createdDateTime":                    graphTimeData(ring.GetCreatedDateTime()),
				"lastModifiedDateTime":               graphTimeData(ring.GetLastModifiedDateTime()),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRing)
	}
	return res, nil
}

// windowsFeatureUpdateProfiles lists the Windows feature update deployment
// profiles. Uses the beta Graph SDK because v1 does not expose them.
// requires DeviceManagementConfiguration.Read.All permission
func (a *mqlMicrosoftDevicemanagement) windowsFeatureUpdateProfiles() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().WindowsFeatureUpdateProfiles().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	profiles, err := iterate[betamodels.WindowsFeatureUpdateProfileable](ctx, resp, graphClient.GetAdapter(), betamodels.CreateWindowsFeatureUpdateProfileCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, p := range profiles {
		mqlProfile, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement.windowsFeatureUpdateProfile",
			map[string]*llx.RawData{
				"__id":                          llx.StringDataPtr(p.GetId()),
				"id":                            llx.StringDataPtr(p.GetId()),
				"displayName":                   llx.StringDataPtr(p.GetDisplayName()),
				"description":                   llx.StringDataPtr(p.GetDescription()),
				"featureUpdateVersion":          llx.StringDataPtr(p.GetFeatureUpdateVersion()),
				"deployableContentDisplayName":  llx.StringDataPtr(p.GetDeployableContentDisplayName()),
				"installFeatureUpdatesOptional": llx.BoolDataPtr(p.GetInstallFeatureUpdatesOptional()),
				"endOfSupportDate":              graphTimeData(p.GetEndOfSupportDate()),
				"roleScopeTagIds":               llx.ArrayData(llx.TArr2Raw(p.GetRoleScopeTagIds()), types.String),
				"createdDateTime":               graphTimeData(p.GetCreatedDateTime()),
				"lastModifiedDateTime":          graphTimeData(p.GetLastModifiedDateTime()),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlProfile)
	}
	return res, nil
}

// windowsQualityUpdateProfiles lists the Windows quality update deployment
// profiles. Uses the beta Graph SDK because v1 does not expose them.
// requires DeviceManagementConfiguration.Read.All permission
func (a *mqlMicrosoftDevicemanagement) windowsQualityUpdateProfiles() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().WindowsQualityUpdateProfiles().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	profiles, err := iterate[betamodels.WindowsQualityUpdateProfileable](ctx, resp, graphClient.GetAdapter(), betamodels.CreateWindowsQualityUpdateProfileCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, p := range profiles {
		var expeditedRelease *string
		var expeditedReboot *int32
		if e := p.GetExpeditedUpdateSettings(); e != nil {
			expeditedRelease = e.GetQualityUpdateRelease()
			expeditedReboot = e.GetDaysUntilForcedReboot()
		}

		mqlProfile, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement.windowsQualityUpdateProfile",
			map[string]*llx.RawData{
				"__id":                           llx.StringDataPtr(p.GetId()),
				"id":                             llx.StringDataPtr(p.GetId()),
				"displayName":                    llx.StringDataPtr(p.GetDisplayName()),
				"description":                    llx.StringDataPtr(p.GetDescription()),
				"deployableContentDisplayName":   llx.StringDataPtr(p.GetDeployableContentDisplayName()),
				"releaseDateDisplayName":         llx.StringDataPtr(p.GetReleaseDateDisplayName()),
				"expeditedQualityUpdateRelease":  llx.StringDataPtr(expeditedRelease),
				"expeditedDaysUntilForcedReboot": llx.IntDataPtr(expeditedReboot),
				"roleScopeTagIds":                llx.ArrayData(llx.TArr2Raw(p.GetRoleScopeTagIds()), types.String),
				"createdDateTime":                graphTimeData(p.GetCreatedDateTime()),
				"lastModifiedDateTime":           graphTimeData(p.GetLastModifiedDateTime()),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlProfile)
	}
	return res, nil
}
