// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

func (m *mqlMicrosoftDevicemanagementDetectedapp) id() (string, error) {
	return m.Id.Data, nil
}

func (m *mqlMicrosoftDevicemanagementMobileapp) id() (string, error) {
	return m.Id.Data, nil
}

func (a *mqlMicrosoftDevicemanagement) detectedApps() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().DetectedApps().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	apps, err := iterate[models.DetectedAppable](ctx, resp, graphClient.GetAdapter(), models.CreateDetectedAppCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, app := range apps {
		r, err := newDetectedAppResource(a.MqlRuntime, app)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// detectedApps on a managed device uses the beta Graph SDK because v1 does
// not expose the /deviceManagement/managedDevices/{id}/detectedApps navigation.
func (a *mqlMicrosoftDevicemanagementManageddevice) detectedApps() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().ManagedDevices().ByManagedDeviceId(a.Id.Data).DetectedApps().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	apps, err := iterate[betamodels.DetectedAppable](ctx, resp, graphClient.GetAdapter(), betamodels.CreateDetectedAppCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, app := range apps {
		r, err := newBetaDetectedAppResource(a.MqlRuntime, app)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func newBetaDetectedAppResource(runtime *plugin.Runtime, app betamodels.DetectedAppable) (any, error) {
	platform := ""
	if v := app.GetPlatform(); v != nil {
		platform = v.String()
	}
	deviceCount := int64(0)
	if v := app.GetDeviceCount(); v != nil {
		deviceCount = int64(*v)
	}
	return CreateResource(runtime, "microsoft.devicemanagement.detectedapp",
		map[string]*llx.RawData{
			"__id":        llx.StringDataPtr(app.GetId()),
			"id":          llx.StringDataPtr(app.GetId()),
			"displayName": llx.StringDataPtr(app.GetDisplayName()),
			"version":     llx.StringDataPtr(app.GetVersion()),
			"sizeInByte":  llx.IntDataDefault(app.GetSizeInByte(), 0),
			"deviceCount": llx.IntData(deviceCount),
			"platform":    llx.StringData(platform),
			"publisher":   llx.StringDataPtr(app.GetPublisher()),
		})
}

func newDetectedAppResource(runtime *plugin.Runtime, app models.DetectedAppable) (any, error) {
	platform := ""
	if v := app.GetPlatform(); v != nil {
		platform = v.String()
	}
	deviceCount := int64(0)
	if v := app.GetDeviceCount(); v != nil {
		deviceCount = int64(*v)
	}
	return CreateResource(runtime, "microsoft.devicemanagement.detectedapp",
		map[string]*llx.RawData{
			"__id":        llx.StringDataPtr(app.GetId()),
			"id":          llx.StringDataPtr(app.GetId()),
			"displayName": llx.StringDataPtr(app.GetDisplayName()),
			"version":     llx.StringDataPtr(app.GetVersion()),
			"sizeInByte":  llx.IntDataDefault(app.GetSizeInByte(), 0),
			"deviceCount": llx.IntData(deviceCount),
			"platform":    llx.StringData(platform),
			"publisher":   llx.StringDataPtr(app.GetPublisher()),
		})
}

func (a *mqlMicrosoftDevicemanagement) mobileApps() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.DeviceAppManagement().MobileApps().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	apps, err := iterate[models.MobileAppable](ctx, resp, graphClient.GetAdapter(), models.CreateMobileAppCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, app := range apps {
		r, err := newMobileAppResource(a.MqlRuntime, app)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func newMobileAppResource(runtime *plugin.Runtime, app models.MobileAppable) (any, error) {
	publishingState := ""
	if v := app.GetPublishingState(); v != nil {
		publishingState = v.String()
	}
	props, err := mobileAppProperties(app)
	if err != nil {
		return nil, err
	}
	return CreateResource(runtime, "microsoft.devicemanagement.mobileapp",
		map[string]*llx.RawData{
			"__id":                  llx.StringDataPtr(app.GetId()),
			"id":                    llx.StringDataPtr(app.GetId()),
			"displayName":           llx.StringDataPtr(app.GetDisplayName()),
			"description":           llx.StringDataPtr(app.GetDescription()),
			"publisher":             llx.StringDataPtr(app.GetPublisher()),
			"isFeatured":            llx.BoolDataPtr(app.GetIsFeatured()),
			"privacyInformationUrl": llx.StringDataPtr(app.GetPrivacyInformationUrl()),
			"informationUrl":        llx.StringDataPtr(app.GetInformationUrl()),
			"publishingState":       llx.StringData(publishingState),
			"createdDateTime":       llx.TimeDataPtr(app.GetCreatedDateTime()),
			"lastModifiedDateTime":  llx.TimeDataPtr(app.GetLastModifiedDateTime()),
			"properties":            llx.DictData(props),
		})
}

// mobileAppBaseProperties are the properties every mobileApp type declares.
// They are left out of `properties`, which holds what the concrete app type
// adds (bundleId, appStoreUrl, packageId, installCommandLine, ...).
var mobileAppBaseProperties = func() map[string]struct{} {
	res := map[string]struct{}{}
	for k := range models.NewMobileApp().GetFieldDeserializers() {
		res[k] = struct{}{}
	}
	return res
}()

// mobileAppProperties returns the type-specific properties of a mobile app,
// with `@odata.type` trimmed to the bare type name (iosStoreApp,
// win32LobApp, ...).
func mobileAppProperties(app models.MobileAppable) (map[string]any, error) {
	all, err := kiotaToDict(app)
	if err != nil {
		return nil, err
	}
	props := map[string]any{}
	for k, v := range all {
		if _, ok := mobileAppBaseProperties[k]; ok {
			continue
		}
		props[k] = v
	}
	if v := app.GetOdataType(); v != nil {
		props["@odata.type"] = trimOdataType(*v)
	}
	return props, nil
}

func (a *mqlMicrosoftDevicemanagementMobileapp) assignments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.DeviceAppManagement().MobileApps().ByMobileAppId(a.Id.Data).Assignments().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	assignments, err := iterate[models.MobileAppAssignmentable](ctx, resp, graphClient.GetAdapter(), models.CreateMobileAppAssignmentCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, assignment := range assignments {
		id := ""
		if v := assignment.GetId(); v != nil {
			id = *v
		}
		r, err := newPolicyAssignmentResource(a.MqlRuntime, a.Id.Data+"/"+id, assignment.GetTarget())
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}
