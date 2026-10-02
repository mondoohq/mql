// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	abstractions "github.com/microsoft/kiota-abstractions-go"
	"github.com/microsoftgraph/msgraph-sdk-go/devices"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// see https://learn.microsoft.com/en-us/graph/api/resources/device?view=graph-rest-1.0
var deviceSelectFields = []string{
	"id", "displayName", "deviceId", "deviceCategory", "enrollmentProfileName", "enrollmentType",
	"isCompliant", "isManaged", "manufacturer", "isRooted", "mdmAppId", "model", "operatingSystem",
	"operatingSystemVersion", "physicalIds", "registrationDateTime", "systemLabels", "trustType",
	"accountEnabled", "deletedDateTime", "onPremisesSyncEnabled", "onPremisesLastSyncDateTime",
	"profileType", "approximateLastSignInDateTime", "deviceOwnership", "complianceExpirationDateTime",
}

func initMicrosoftDevices(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	args["__id"] = newListResourceIdFromArguments("microsoft.devices", args)
	resource, err := runtime.CreateResource(runtime, "microsoft.devices", args)
	if err != nil {
		return args, nil, err
	}

	return args, resource.(*mqlMicrosoftDevices), nil
}

// list fetches devices from Entra ID and allows the user provide a filter to retrieve
// a subset of devices
//
// Permissions: Device.Read.All
// see https://learn.microsoft.com/en-us/graph/api/device-list?view=graph-rest-1.0&tabs=http
func (a *mqlMicrosoftDevices) list() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	// Index of devices are stored inside the top level resource `microsoft`, so
	// we create or get the resource to access those internals.
	mainResource, err := CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	microsoft := mainResource.(*mqlMicrosoft)

	// fetch device data
	ctx := context.Background()
	top := int32(999)
	opts := &devices.DevicesRequestBuilderGetRequestConfiguration{
		QueryParameters: &devices.DevicesRequestBuilderGetQueryParameters{
			Select: deviceSelectFields,
			Top:    &top,
		},
	}

	if a.Search.State == plugin.StateIsSet || a.Filter.State == plugin.StateIsSet {
		// search and filter requires this header
		headers := abstractions.NewRequestHeaders()
		headers.Add("ConsistencyLevel", "eventual")
		opts.Headers = headers

		if a.Search.State == plugin.StateIsSet {
			log.Debug().
				Str("search", a.Search.Data).
				Msg("microsoft.devices.list.search set")
			search, err := parseSearch(a.Search.Data)
			if err != nil {
				return nil, err
			}
			opts.QueryParameters.Search = &search
		}
		if a.Filter.State == plugin.StateIsSet {
			log.Debug().
				Str("filter", a.Filter.Data).
				Msg("microsoft.devices.list.filter set")
			opts.QueryParameters.Filter = &a.Filter.Data
			count := true
			opts.QueryParameters.Count = &count
		}
	}

	resp, err := graphClient.Devices().Get(ctx, opts)
	if err != nil {
		return nil, transformError(err)
	}
	devices, err := iterate[*models.Device](ctx,
		resp,
		graphClient.GetAdapter(),
		devices.CreateDeltaGetResponseFromDiscriminatorValue,
	)
	if err != nil {
		return nil, transformError(err)
	}

	// construct the result
	res := []any{}
	for _, u := range devices {
		graphDevice, err := newMqlMicrosoftDevice(a.MqlRuntime, u)
		if err != nil {
			return nil, err
		}
		// indexUser devices by id
		microsoft.indexDevice(graphDevice)
		res = append(res, graphDevice)
	}

	return res, nil
}

func initMicrosoftDevice(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// we only look up the user if we have been supplied by id, displayName or userPrincipalName
	if len(args) > 1 {
		return args, nil, nil
	}

	rawId, okId := args["id"]
	rawDisplayName, okDisplayName := args["displayName"]

	if !okId && !okDisplayName {
		// required parameters are not set, we just pass-through the initialization arguments
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()

	// Fast path: look up directly by id. Skips the redundant filter+get
	// round-trip we'd otherwise pay for every microsoft.device(id: "...")
	// reference.
	if okId {
		device, err := graphClient.Devices().ByDeviceId(rawId.Value.(string)).Get(ctx, &devices.DeviceItemRequestBuilderGetRequestConfiguration{
			QueryParameters: &devices.DeviceItemRequestBuilderGetQueryParameters{
				Select: deviceSelectFields,
			},
		})
		if err != nil {
			return nil, nil, transformError(err)
		}
		mqlMsApp, err := newMqlMicrosoftDevice(runtime, device)
		if err != nil {
			return nil, nil, err
		}
		return nil, mqlMsApp, nil
	}

	displayNameFilter := fmt.Sprintf("displayName eq '%s'", rawDisplayName.Value.(string))
	resp, err := graphClient.Devices().Get(ctx, &devices.DevicesRequestBuilderGetRequestConfiguration{
		QueryParameters: &devices.DevicesRequestBuilderGetQueryParameters{
			Filter: &displayNameFilter,
			Select: deviceSelectFields,
		},
	})
	if err != nil {
		return nil, nil, transformError(err)
	}

	val := resp.GetValue()
	if len(val) == 0 {
		return nil, nil, errors.New("device not found")
	}

	// Reuse the filter response directly — the requested Select carries
	// every field newMqlMicrosoftDevice consumes, so a second Get by id
	// would just return the same data.
	mqlMsApp, err := newMqlMicrosoftDevice(runtime, val[0])
	if err != nil {
		return nil, nil, err
	}

	return nil, mqlMsApp, nil
}

func newMqlMicrosoftDevice(runtime *plugin.Runtime, u models.Deviceable) (*mqlMicrosoftDevice, error) {
	graphDevice, err := CreateResource(runtime, "microsoft.device",
		map[string]*llx.RawData{
			"__id":                          llx.StringDataPtr(u.GetId()),
			"id":                            llx.StringDataPtr(u.GetId()),
			"displayName":                   llx.StringDataPtr(u.GetDisplayName()),
			"deviceId":                      llx.StringDataPtr(u.GetDeviceId()),
			"deviceCategory":                llx.StringDataPtr(u.GetDeviceCategory()),
			"enrollmentProfileName":         llx.StringDataPtr(u.GetEnrollmentProfileName()),
			"enrollmentType":                llx.StringDataPtr(u.GetEnrollmentType()),
			"isCompliant":                   llx.BoolDataPtr(u.GetIsCompliant()),
			"isManaged":                     llx.BoolDataPtr(u.GetIsManaged()),
			"manufacturer":                  llx.StringDataPtr(u.GetManufacturer()),
			"isRooted":                      llx.BoolDataPtr(u.GetIsRooted()),
			"mdmAppId":                      llx.StringDataPtr(u.GetMdmAppId()),
			"model":                         llx.StringDataPtr(u.GetModel()),
			"operatingSystem":               llx.StringDataPtr(u.GetOperatingSystem()),
			"operatingSystemVersion":        llx.StringDataPtr(u.GetOperatingSystemVersion()),
			"physicalIds":                   llx.ArrayData(convert.SliceAnyToInterface(u.GetPhysicalIds()), types.String),
			"registrationDateTime":          graphTimeData(u.GetRegistrationDateTime()),
			"systemLabels":                  llx.ArrayData(convert.SliceAnyToInterface(u.GetSystemLabels()), types.String),
			"trustType":                     llx.StringDataPtr(u.GetTrustType()),
			"accountEnabled":                llx.BoolDataPtr(u.GetAccountEnabled()),
			"deletedDateTime":               graphTimeData(u.GetDeletedDateTime()),
			"onPremisesSyncEnabled":         llx.BoolDataPtr(u.GetOnPremisesSyncEnabled()),
			"onPremisesLastSyncDateTime":    graphTimeData(u.GetOnPremisesLastSyncDateTime()),
			"profileType":                   llx.StringDataPtr(u.GetProfileType()),
			"approximateLastSignInDateTime": graphTimeData(u.GetApproximateLastSignInDateTime()),
			"deviceOwnership":               llx.StringDataPtr(u.GetDeviceOwnership()),
			"complianceExpirationDateTime":  graphTimeData(u.GetComplianceExpirationDateTime()),
		})
	if err != nil {
		return nil, err
	}
	return graphDevice.(*mqlMicrosoftDevice), nil
}
