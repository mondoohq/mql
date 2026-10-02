// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// appProtectionPolicies returns Intune app protection (MAM) policies for iOS
// and Android, merged into a single list discriminated by platformType.
// requires DeviceManagementApps.Read.All permission
func (a *mqlMicrosoftDevicemanagement) appProtectionPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	res := []any{}

	iosResp, err := graphClient.DeviceAppManagement().IosManagedAppProtections().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	iosPolicies, err := iterate[models.IosManagedAppProtectionable](ctx, iosResp, graphClient.GetAdapter(), models.CreateIosManagedAppProtectionCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}
	for _, p := range iosPolicies {
		mqlPolicy, err := newMqlAppProtectionPolicy(a.MqlRuntime, p, "ios")
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPolicy)
	}

	androidResp, err := graphClient.DeviceAppManagement().AndroidManagedAppProtections().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	androidPolicies, err := iterate[models.AndroidManagedAppProtectionable](ctx, androidResp, graphClient.GetAdapter(), models.CreateAndroidManagedAppProtectionCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}
	for _, p := range androidPolicies {
		mqlPolicy, err := newMqlAppProtectionPolicy(a.MqlRuntime, p, "android")
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPolicy)
	}

	return res, nil
}

func isoDurationString(d interface{ String() string }) *string {
	if d == nil {
		return nil
	}
	s := d.String()
	return &s
}

func newMqlAppProtectionPolicy(runtime *plugin.Runtime, p models.TargetedManagedAppProtectionable, platform string) (plugin.Resource, error) {
	var periodOfflineBeforeAccessCheck, periodOnlineBeforeAccessCheck, periodOfflineBeforeWipe *string
	if d := p.GetPeriodOfflineBeforeAccessCheck(); d != nil {
		periodOfflineBeforeAccessCheck = isoDurationString(d)
	}
	if d := p.GetPeriodOnlineBeforeAccessCheck(); d != nil {
		periodOnlineBeforeAccessCheck = isoDurationString(d)
	}
	if d := p.GetPeriodOfflineBeforeWipeIsEnforced(); d != nil {
		periodOfflineBeforeWipe = isoDurationString(d)
	}

	return CreateResource(runtime, "microsoft.devicemanagement.appProtectionPolicy",
		map[string]*llx.RawData{
			"__id":                                    llx.StringDataPtr(p.GetId()),
			"id":                                      llx.StringDataPtr(p.GetId()),
			"displayName":                             llx.StringDataPtr(p.GetDisplayName()),
			"description":                             llx.StringDataPtr(p.GetDescription()),
			"platformType":                            llx.StringData(platform),
			"createdDateTime":                         graphTimeData(p.GetCreatedDateTime()),
			"lastModifiedDateTime":                    graphTimeData(p.GetLastModifiedDateTime()),
			"version":                                 llx.StringDataPtr(p.GetVersion()),
			"isAssigned":                              llx.BoolDataPtr(p.GetIsAssigned()),
			"pinRequired":                             llx.BoolDataPtr(p.GetPinRequired()),
			"minimumPinLength":                        llx.IntDataPtr(p.GetMinimumPinLength()),
			"maximumPinRetries":                       llx.IntDataPtr(p.GetMaximumPinRetries()),
			"simplePinBlocked":                        llx.BoolDataPtr(p.GetSimplePinBlocked()),
			"pinCharacterSet":                         llx.StringDataPtr(enumPtrString(p.GetPinCharacterSet())),
			"fingerprintBlocked":                      llx.BoolDataPtr(p.GetFingerprintBlocked()),
			"disableAppPinIfDevicePinIsSet":           llx.BoolDataPtr(p.GetDisableAppPinIfDevicePinIsSet()),
			"organizationalCredentialsRequired":       llx.BoolDataPtr(p.GetOrganizationalCredentialsRequired()),
			"periodOfflineBeforeAccessCheck":          llx.StringDataPtr(periodOfflineBeforeAccessCheck),
			"periodOnlineBeforeAccessCheck":           llx.StringDataPtr(periodOnlineBeforeAccessCheck),
			"periodOfflineBeforeWipeIsEnforced":       llx.StringDataPtr(periodOfflineBeforeWipe),
			"dataBackupBlocked":                       llx.BoolDataPtr(p.GetDataBackupBlocked()),
			"deviceComplianceRequired":                llx.BoolDataPtr(p.GetDeviceComplianceRequired()),
			"managedBrowserToOpenLinksRequired":       llx.BoolDataPtr(p.GetManagedBrowserToOpenLinksRequired()),
			"saveAsBlocked":                           llx.BoolDataPtr(p.GetSaveAsBlocked()),
			"printBlocked":                            llx.BoolDataPtr(p.GetPrintBlocked()),
			"contactSyncBlocked":                      llx.BoolDataPtr(p.GetContactSyncBlocked()),
			"allowedDataStorageLocations":             llx.ArrayData(enumSliceToInterface(p.GetAllowedDataStorageLocations()), types.String),
			"allowedInboundDataTransferSources":       llx.StringDataPtr(enumPtrString(p.GetAllowedInboundDataTransferSources())),
			"allowedOutboundDataTransferDestinations": llx.StringDataPtr(enumPtrString(p.GetAllowedOutboundDataTransferDestinations())),
			"allowedOutboundClipboardSharingLevel":    llx.StringDataPtr(enumPtrString(p.GetAllowedOutboundClipboardSharingLevel())),
			"managedBrowser":                          llx.StringDataPtr(enumPtrString(p.GetManagedBrowser())),
			"minimumRequiredOsVersion":                llx.StringDataPtr(p.GetMinimumRequiredOsVersion()),
			"minimumRequiredAppVersion":               llx.StringDataPtr(p.GetMinimumRequiredAppVersion()),
		})
}

// enumSliceToInterface renders a slice of Graph enum values as their string
// representations.
func enumSliceToInterface[T interface{ String() string }](items []T) []any {
	res := make([]any, 0, len(items))
	for _, item := range items {
		res = append(res, item.String())
	}
	return res
}
