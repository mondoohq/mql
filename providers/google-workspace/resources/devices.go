// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/google-workspace/connection"
	"go.mondoo.com/mql/types"
	directory "google.golang.org/api/admin/directory/v1"
)

// epochMillisToTime converts an epoch-milliseconds timestamp (the format the
// Directory API uses for Chrome OS auto-update expiration) into a time. A
// zero/negative value means the field is unset, which surfaces as null.
func epochMillisToTime(ms int64) *time.Time {
	if ms <= 0 {
		return nil
	}
	t := time.UnixMilli(ms)
	return &t
}

func (g *mqlGoogleworkspace) chromeOsDevices() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
	directoryService, err := directoryService(conn, directory.AdminDirectoryDeviceChromeosReadonlyScope)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageToken := ""
	for {
		// FULL projection includes the posture fields (bootMode, osVersion,
		// firmwareVersion, autoUpdateExpiration, ...) that BASIC omits.
		call := directoryService.Chromeosdevices.List(conn.CustomerID()).Projection("FULL").MaxResults(200)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		devices, err := call.Do()
		if err != nil {
			return nil, err
		}
		for i := range devices.Chromeosdevices {
			r, err := newMqlGoogleWorkspaceChromeOsDevice(g.MqlRuntime, devices.Chromeosdevices[i])
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}
		if devices.NextPageToken == "" {
			break
		}
		pageToken = devices.NextPageToken
	}
	return res, nil
}

func newMqlGoogleWorkspaceChromeOsDevice(runtime *plugin.Runtime, entry *directory.ChromeOsDevice) (any, error) {
	return CreateResource(runtime, "googleworkspace.chromeOsDevice", map[string]*llx.RawData{
		"id":                   llx.StringData(entry.DeviceId),
		"serialNumber":         llx.StringData(entry.SerialNumber),
		"status":               llx.StringData(entry.Status),
		"model":                llx.StringData(entry.Model),
		"osVersion":            llx.StringData(entry.OsVersion),
		"platformVersion":      llx.StringData(entry.PlatformVersion),
		"firmwareVersion":      llx.StringData(entry.FirmwareVersion),
		"bootMode":             llx.StringData(entry.BootMode),
		"osVersionCompliance":  llx.StringData(entry.OsVersionCompliance),
		"orgUnitPath":          llx.StringData(entry.OrgUnitPath),
		"macAddress":           llx.StringData(entry.MacAddress),
		"annotatedUser":        llx.StringData(entry.AnnotatedUser),
		"annotatedLocation":    llx.StringData(entry.AnnotatedLocation),
		"annotatedAssetId":     llx.StringData(entry.AnnotatedAssetId),
		"notes":                llx.StringData(entry.Notes),
		"deprovisionReason":    llx.StringData(entry.DeprovisionReason),
		"deviceLicenseType":    llx.StringData(entry.DeviceLicenseType),
		"lastSync":             llx.TimeDataPtr(parseRFC3339(entry.LastSync)),
		"firstEnrollmentTime":  llx.TimeDataPtr(parseRFC3339(entry.FirstEnrollmentTime)),
		"lastEnrollmentTime":   llx.TimeDataPtr(parseRFC3339(entry.LastEnrollmentTime)),
		"autoUpdateExpiration": llx.TimeDataPtr(epochMillisToTime(entry.AutoUpdateExpiration)),
	})
}

func (g *mqlGoogleworkspaceChromeOsDevice) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "googleworkspace.chromeOsDevice/" + g.Id.Data, nil
}

func (g *mqlGoogleworkspace) mobileDevices() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
	directoryService, err := directoryService(conn, directory.AdminDirectoryDeviceMobileReadonlyScope)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageToken := ""
	for {
		// FULL projection includes the posture fields (compromised, encryption,
		// password, developer options, ADB, unknown sources) BASIC omits.
		call := directoryService.Mobiledevices.List(conn.CustomerID()).Projection("FULL").MaxResults(100)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		devices, err := call.Do()
		if err != nil {
			return nil, err
		}
		for i := range devices.Mobiledevices {
			r, err := newMqlGoogleWorkspaceMobileDevice(g.MqlRuntime, devices.Mobiledevices[i])
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}
		if devices.NextPageToken == "" {
			break
		}
		pageToken = devices.NextPageToken
	}
	return res, nil
}

func newMqlGoogleWorkspaceMobileDevice(runtime *plugin.Runtime, entry *directory.MobileDevice) (any, error) {
	return CreateResource(runtime, "googleworkspace.mobileDevice", map[string]*llx.RawData{
		"id":                             llx.StringData(entry.ResourceId),
		"deviceId":                       llx.StringData(entry.DeviceId),
		"type":                           llx.StringData(entry.Type),
		"status":                         llx.StringData(entry.Status),
		"model":                          llx.StringData(entry.Model),
		"os":                             llx.StringData(entry.Os),
		"releaseVersion":                 llx.StringData(entry.ReleaseVersion),
		"deviceCompromisedStatus":        llx.StringData(entry.DeviceCompromisedStatus),
		"encryptionStatus":               llx.StringData(entry.EncryptionStatus),
		"devicePasswordStatus":           llx.StringData(entry.DevicePasswordStatus),
		"developerOptionsStatus":         llx.BoolData(entry.DeveloperOptionsStatus),
		"adbStatus":                      llx.BoolData(entry.AdbStatus),
		"unknownSourcesStatus":           llx.BoolData(entry.UnknownSourcesStatus),
		"supportsWorkProfile":            llx.BoolData(entry.SupportsWorkProfile),
		"managedAccountIsOnOwnerProfile": llx.BoolData(entry.ManagedAccountIsOnOwnerProfile),
		"privilege":                      llx.StringData(entry.Privilege),
		"manufacturer":                   llx.StringData(entry.Manufacturer),
		"brand":                          llx.StringData(entry.Brand),
		"hardware":                       llx.StringData(entry.Hardware),
		"imei":                           llx.StringData(entry.Imei),
		"meid":                           llx.StringData(entry.Meid),
		"serialNumber":                   llx.StringData(entry.SerialNumber),
		"wifiMacAddress":                 llx.StringData(entry.WifiMacAddress),
		"networkOperator":                llx.StringData(entry.NetworkOperator),
		"defaultLanguage":                llx.StringData(entry.DefaultLanguage),
		"userAgent":                      llx.StringData(entry.UserAgent),
		"securityPatchLevel":             llx.IntData(entry.SecurityPatchLevel),
		"emails":                         llx.ArrayData(convert.SliceAnyToInterface[string](entry.Email), types.String),
		"names":                          llx.ArrayData(convert.SliceAnyToInterface[string](entry.Name), types.String),
		"otherAccountsInfo":              llx.ArrayData(convert.SliceAnyToInterface[string](entry.OtherAccountsInfo), types.String),
		"firstSync":                      llx.TimeDataPtr(parseRFC3339(entry.FirstSync)),
		"lastSync":                       llx.TimeDataPtr(parseRFC3339(entry.LastSync)),
	})
}

func (g *mqlGoogleworkspaceMobileDevice) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "googleworkspace.mobileDevice/" + g.Id.Data, nil
}
