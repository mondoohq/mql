// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/microsoftgraph/msgraph-sdk-go/devicemanagement"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

const devicemanagementSettingsID = "microsoft.devicemanagement/settings"

// settings exposes the tenant-wide Intune device management settings. When the
// tenant has no Intune device management configuration the Graph settings
// object is null, in which case every field resolves to null rather than a
// fabricated zero value.
// requires DeviceManagementConfiguration.Read.All permission
func (a *mqlMicrosoftDevicemanagement) settings() (*mqlMicrosoftDevicemanagementSettings, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	dm, err := graphClient.DeviceManagement().Get(ctx, &devicemanagement.DeviceManagementRequestBuilderGetRequestConfiguration{
		QueryParameters: &devicemanagement.DeviceManagementRequestBuilderGetQueryParameters{
			Select: []string{"settings"},
		},
	})
	if err != nil {
		return nil, transformError(err)
	}

	// nil pointers (no Intune settings configured, or a field omitted) flow
	// through the *DataPtr helpers as null rather than a fabricated zero value
	var secureByDefault, scheduledActionEnabled *bool
	var checkinThresholdDays *int32
	if dm != nil && dm.GetSettings() != nil {
		settings := dm.GetSettings()
		secureByDefault = settings.GetSecureByDefault()
		checkinThresholdDays = settings.GetDeviceComplianceCheckinThresholdDays()
		scheduledActionEnabled = settings.GetIsScheduledActionEnabled()
	}

	resource, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement.settings", map[string]*llx.RawData{
		"__id":                                 llx.StringData(devicemanagementSettingsID),
		"secureByDefault":                      llx.BoolDataPtr(secureByDefault),
		"deviceComplianceCheckinThresholdDays": llx.IntDataPtr(checkinThresholdDays),
		"isScheduledActionEnabled":             llx.BoolDataPtr(scheduledActionEnabled),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoftDevicemanagementSettings), nil
}

// initMicrosoftDevicemanagementSettings rebuilds the parent chain so that the
// settings resource can be queried by its full dotted path
// (microsoft.devicemanagement.settings) and not just nested under
// microsoft.devicemanagement. Without it, the dotted form is built as a bare
// husk with no data.
func initMicrosoftDevicemanagementSettings(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	dm, err := CreateResource(runtime, "microsoft.devicemanagement", nil)
	if err != nil {
		return nil, nil, err
	}

	settings, err := dm.(*mqlMicrosoftDevicemanagement).settings()
	if err != nil {
		return nil, nil, err
	}
	return nil, settings, nil
}
