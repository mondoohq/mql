// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/ms365/connection"
)

// mobileThreatDefenseConnectors lists the Mobile Threat Defense partner
// connectors integrated with Intune.
// requires DeviceManagementConfiguration.Read.All permission
func (a *mqlMicrosoftDevicemanagement) mobileThreatDefenseConnectors() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().MobileThreatDefenseConnectors().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	connectors, err := iterate[models.MobileThreatDefenseConnectorable](ctx, resp, graphClient.GetAdapter(), models.CreateMobileThreatDefenseConnectorCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, c := range connectors {
		mqlConnector, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement.mobileThreatDefenseConnector",
			map[string]*llx.RawData{
				"__id":                                   llx.StringDataPtr(c.GetId()),
				"id":                                     llx.StringDataPtr(c.GetId()),
				"partnerState":                           llx.StringDataPtr(enumPtrString(c.GetPartnerState())),
				"lastHeartbeatDateTime":                  graphTimeData(c.GetLastHeartbeatDateTime()),
				"partnerUnresponsivenessThresholdInDays": llx.IntDataPtr(c.GetPartnerUnresponsivenessThresholdInDays()),
				"partnerUnsupportedOsVersionBlocked":     llx.BoolDataPtr(c.GetPartnerUnsupportedOsVersionBlocked()),
				"androidEnabled":                         llx.BoolDataPtr(c.GetAndroidEnabled()),
				"iosEnabled":                             llx.BoolDataPtr(c.GetIosEnabled()),
				"windowsEnabled":                         llx.BoolDataPtr(c.GetWindowsEnabled()),
				"androidMobileApplicationManagementEnabled":           llx.BoolDataPtr(c.GetAndroidMobileApplicationManagementEnabled()),
				"iosMobileApplicationManagementEnabled":               llx.BoolDataPtr(c.GetIosMobileApplicationManagementEnabled()),
				"androidDeviceBlockedOnMissingPartnerData":            llx.BoolDataPtr(c.GetAndroidDeviceBlockedOnMissingPartnerData()),
				"iosDeviceBlockedOnMissingPartnerData":                llx.BoolDataPtr(c.GetIosDeviceBlockedOnMissingPartnerData()),
				"windowsDeviceBlockedOnMissingPartnerData":            llx.BoolDataPtr(c.GetWindowsDeviceBlockedOnMissingPartnerData()),
				"microsoftDefenderForEndpointAttachEnabled":           llx.BoolDataPtr(c.GetMicrosoftDefenderForEndpointAttachEnabled()),
				"allowPartnerToCollectIosApplicationMetadata":         llx.BoolDataPtr(c.GetAllowPartnerToCollectIOSApplicationMetadata()),
				"allowPartnerToCollectIosPersonalApplicationMetadata": llx.BoolDataPtr(c.GetAllowPartnerToCollectIOSPersonalApplicationMetadata()),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlConnector)
	}
	return res, nil
}

// complianceManagementPartners lists the device compliance management partners
// connected to Intune.
// requires DeviceManagementConfiguration.Read.All permission
func (a *mqlMicrosoftDevicemanagement) complianceManagementPartners() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().ComplianceManagementPartners().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	partners, err := iterate[models.ComplianceManagementPartnerable](ctx, resp, graphClient.GetAdapter(), models.CreateComplianceManagementPartnerCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, p := range partners {
		mqlPartner, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement.complianceManagementPartner",
			map[string]*llx.RawData{
				"__id":                  llx.StringDataPtr(p.GetId()),
				"id":                    llx.StringDataPtr(p.GetId()),
				"displayName":           llx.StringDataPtr(p.GetDisplayName()),
				"partnerState":          llx.StringDataPtr(enumPtrString(p.GetPartnerState())),
				"lastHeartbeatDateTime": graphTimeData(p.GetLastHeartbeatDateTime()),
				"androidOnboarded":      llx.BoolDataPtr(p.GetAndroidOnboarded()),
				"iosOnboarded":          llx.BoolDataPtr(p.GetIosOnboarded()),
				"macOsOnboarded":        llx.BoolDataPtr(p.GetMacOsOnboarded()),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPartner)
	}
	return res, nil
}
