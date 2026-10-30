// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// managedAppConfigurations lists the app configuration policies that deliver
// settings to managed apps (MAM).
// requires DeviceManagementApps.Read.All permission
func (a *mqlMicrosoftDevicemanagement) managedAppConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.DeviceAppManagement().TargetedManagedAppConfigurations().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	configs, err := iterate[models.TargetedManagedAppConfigurationable](ctx, resp, graphClient.GetAdapter(), models.CreateTargetedManagedAppConfigurationCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, c := range configs {
		customSettings := map[string]any{}
		for _, kv := range c.GetCustomSettings() {
			if kv.GetName() != nil {
				customSettings[*kv.GetName()] = convert.ToValue(kv.GetValue())
			}
		}

		mqlConfig, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement.managedAppConfiguration",
			map[string]*llx.RawData{
				"__id":                 llx.StringDataPtr(c.GetId()),
				"id":                   llx.StringDataPtr(c.GetId()),
				"displayName":          llx.StringDataPtr(c.GetDisplayName()),
				"description":          llx.StringDataPtr(c.GetDescription()),
				"version":              llx.StringDataPtr(c.GetVersion()),
				"customSettings":       llx.MapData(customSettings, types.String),
				"deployedAppCount":     llx.IntDataPtr(c.GetDeployedAppCount()),
				"isAssigned":           llx.BoolDataPtr(c.GetIsAssigned()),
				"createdDateTime":      graphTimeData(c.GetCreatedDateTime()),
				"lastModifiedDateTime": graphTimeData(c.GetLastModifiedDateTime()),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlConfig)
	}
	return res, nil
}

// mobileAppConfigurations lists the app configuration policies that deliver
// settings to managed devices (MDM).
// requires DeviceManagementApps.Read.All permission
func (a *mqlMicrosoftDevicemanagement) mobileAppConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.DeviceAppManagement().MobileAppConfigurations().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	configs, err := iterate[models.ManagedDeviceMobileAppConfigurationable](ctx, resp, graphClient.GetAdapter(), models.CreateManagedDeviceMobileAppConfigurationCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, c := range configs {
		mqlConfig, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement.mobileAppConfiguration",
			map[string]*llx.RawData{
				"__id":                 llx.StringDataPtr(c.GetId()),
				"id":                   llx.StringDataPtr(c.GetId()),
				"displayName":          llx.StringDataPtr(c.GetDisplayName()),
				"description":          llx.StringDataPtr(c.GetDescription()),
				"version":              llx.IntDataPtr(c.GetVersion()),
				"targetedMobileApps":   llx.ArrayData(llx.TArr2Raw(c.GetTargetedMobileApps()), types.String),
				"createdDateTime":      graphTimeData(c.GetCreatedDateTime()),
				"lastModifiedDateTime": graphTimeData(c.GetLastModifiedDateTime()),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlConfig)
	}
	return res, nil
}
