// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/google-workspace/connection"
	"go.mondoo.com/mql/types"

	cloudidentity "google.golang.org/api/cloudidentity/v1"
)

func (g *mqlGoogleworkspace) endpoints() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
	service, err := cloudIdentityService(conn, cloudidentity.CloudIdentityDevicesReadonlyScope)
	if err != nil {
		return nil, err
	}

	customer := "customers/" + conn.CustomerID()
	seen := map[string]struct{}{}
	res := []any{}

	// Query both views to cover company-imported devices and user-assigned
	// devices (Endpoint Verification, GCPW, BYOD mobile). The API does not
	// return both in a single call; we dedupe by Name.
	for _, view := range []string{"COMPANY_INVENTORY", "USER_ASSIGNED_DEVICES"} {
		pageToken := ""
		for {
			call := service.Devices.List().Customer(customer).View(view).PageSize(100)
			if pageToken != "" {
				call = call.PageToken(pageToken)
			}
			resp, err := call.Do()
			if err != nil {
				return nil, err
			}
			for _, d := range resp.Devices {
				if _, dup := seen[d.Name]; dup {
					continue
				}
				seen[d.Name] = struct{}{}
				r, err := newMqlGoogleWorkspaceEndpoint(g.MqlRuntime, d)
				if err != nil {
					return nil, err
				}
				res = append(res, r)
			}
			if resp.NextPageToken == "" {
				break
			}
			pageToken = resp.NextPageToken
		}
	}

	return res, nil
}

func newMqlGoogleWorkspaceEndpoint(runtime *plugin.Runtime, entry *cloudidentity.GoogleAppsCloudidentityDevicesV1Device) (any, error) {
	// Leave these as a true nil (rendered as null) when the device didn't
	// report the attribute group. convert.JsonToDict on a nil pointer returns a
	// non-nil empty map, which would surface as `{}` and defeat `x != null`
	// audits (the .lr doc promises null on platforms that don't report it).
	var err error
	var androidAttrs any
	if entry.AndroidSpecificAttributes != nil {
		androidAttrs, err = convert.JsonToDict(entry.AndroidSpecificAttributes)
		if err != nil {
			return nil, err
		}
	}
	var endpointVerificationAttrs any
	if entry.EndpointVerificationSpecificAttributes != nil {
		endpointVerificationAttrs, err = convert.JsonToDict(entry.EndpointVerificationSpecificAttributes)
		if err != nil {
			return nil, err
		}
	}

	signals := parseEndpointAdditionalSignals(entry.EndpointVerificationSpecificAttributes)

	args := map[string]*llx.RawData{
		"id":                             llx.StringData(entry.DeviceId),
		"name":                           llx.StringData(entry.Name),
		"deviceType":                     llx.StringData(entry.DeviceType),
		"ownerType":                      llx.StringData(entry.OwnerType),
		"managementState":                llx.StringData(entry.ManagementState),
		"compromisedState":               llx.StringData(entry.CompromisedState),
		"encryptionState":                llx.StringData(entry.EncryptionState),
		"manufacturer":                   llx.StringData(entry.Manufacturer),
		"brand":                          llx.StringData(entry.Brand),
		"model":                          llx.StringData(entry.Model),
		"serialNumber":                   llx.StringData(entry.SerialNumber),
		"assetTag":                       llx.StringData(entry.AssetTag),
		"hostname":                       llx.StringData(entry.Hostname),
		"osVersion":                      llx.StringData(entry.OsVersion),
		"releaseVersion":                 llx.StringData(entry.ReleaseVersion),
		"buildNumber":                    llx.StringData(entry.BuildNumber),
		"kernelVersion":                  llx.StringData(entry.KernelVersion),
		"basebandVersion":                llx.StringData(entry.BasebandVersion),
		"bootloaderVersion":              llx.StringData(entry.BootloaderVersion),
		"imei":                           llx.StringData(entry.Imei),
		"meid":                           llx.StringData(entry.Meid),
		"wifiMacAddresses":               llx.ArrayData(convert.SliceAnyToInterface[string](entry.WifiMacAddresses), types.String),
		"networkOperator":                llx.StringData(entry.NetworkOperator),
		"enabledDeveloperOptions":        llx.BoolData(entry.EnabledDeveloperOptions),
		"enabledUsbDebugging":            llx.BoolData(entry.EnabledUsbDebugging),
		"otherAccounts":                  llx.ArrayData(convert.SliceAnyToInterface[string](entry.OtherAccounts), types.String),
		"unifiedDeviceId":                llx.StringData(entry.UnifiedDeviceId),
		"securityPatchTime":              llx.TimeDataPtr(parseRFC3339(entry.SecurityPatchTime)),
		"createTime":                     llx.TimeDataPtr(parseRFC3339(entry.CreateTime)),
		"lastSyncTime":                   llx.TimeDataPtr(parseRFC3339(entry.LastSyncTime)),
		"androidAttributes":              llx.DictData(androidAttrs),
		"endpointVerificationAttributes": llx.DictData(endpointVerificationAttrs),
		"windowsDomainName":              llx.StringData(signals.WindowsDomainName),
	}
	// Only set the booleans when the device actually reported them. Leaving
	// the key unset surfaces as null on query, which is what auditors want for
	// "device does not report AV/firewall/secureBoot state" — false would be
	// indistinguishable from "explicitly disabled".
	if signals.AvInstalled != nil {
		args["antivirusInstalled"] = llx.BoolData(*signals.AvInstalled)
	}
	if signals.AvEnabled != nil {
		args["antivirusEnabled"] = llx.BoolData(*signals.AvEnabled)
	}
	if signals.IsOsNativeFirewallEnabled != nil {
		args["osFirewallEnabled"] = llx.BoolData(*signals.IsOsNativeFirewallEnabled)
	}
	if signals.IsSecureBootEnabled != nil {
		args["secureBootEnabled"] = llx.BoolData(*signals.IsSecureBootEnabled)
	}

	return CreateResource(runtime, "googleworkspace.endpoint", args)
}

// endpointAdditionalSignals mirrors the documented shape of
// EndpointVerificationSpecificAttributes.additionalSignals (a googleapi.RawMessage).
// `*bool` lets us distinguish "device did not report this signal" (nil) from
// "device reported false" — auditors generally want these separated.
type endpointAdditionalSignals struct {
	AvInstalled               *bool  `json:"av_installed,omitempty"`
	AvEnabled                 *bool  `json:"av_enabled,omitempty"`
	IsOsNativeFirewallEnabled *bool  `json:"is_os_native_firewall_enabled,omitempty"`
	IsSecureBootEnabled       *bool  `json:"is_secure_boot_enabled,omitempty"`
	WindowsDomainName         string `json:"windows_domain_name,omitempty"`
}

func parseEndpointAdditionalSignals(attrs *cloudidentity.GoogleAppsCloudidentityDevicesV1EndpointVerificationSpecificAttributes) endpointAdditionalSignals {
	var sig endpointAdditionalSignals
	if attrs == nil || len(attrs.AdditionalSignals) == 0 {
		return sig
	}
	// AdditionalSignals is googleapi.RawMessage; Unmarshal errors mean the
	// payload changed shape — skip rather than fail the whole device listing.
	_ = json.Unmarshal(attrs.AdditionalSignals, &sig)
	return sig
}

func parseRFC3339(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		log.Debug().Err(err).Str("value", s).Msg("google-workspace: failed to parse RFC3339 timestamp")
		return nil
	}
	return &t
}

func (g *mqlGoogleworkspaceEndpoint) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "googleworkspace.endpoint/" + g.Id.Data, nil
}

func (g *mqlGoogleworkspaceEndpoint) users() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
	service, err := cloudIdentityService(conn, cloudidentity.CloudIdentityDevicesReadonlyScope)
	if err != nil {
		return nil, err
	}

	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	parent := g.Name.Data
	if parent == "" {
		return []any{}, nil
	}

	customer := "customers/" + conn.CustomerID()
	res := []any{}
	pageToken := ""
	for {
		call := service.Devices.DeviceUsers.List(parent).Customer(customer).PageSize(20)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}
		resp, err := call.Do()
		if err != nil {
			return nil, err
		}
		for _, du := range resp.DeviceUsers {
			r, err := newMqlGoogleWorkspaceEndpointUser(g.MqlRuntime, du)
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}
	return res, nil
}

func newMqlGoogleWorkspaceEndpointUser(runtime *plugin.Runtime, entry *cloudidentity.GoogleAppsCloudidentityDevicesV1DeviceUser) (any, error) {
	return CreateResource(runtime, "googleworkspace.endpoint.user", map[string]*llx.RawData{
		"id":               llx.StringData(entry.Name),
		"userEmail":        llx.StringData(entry.UserEmail),
		"managementState":  llx.StringData(entry.ManagementState),
		"compromisedState": llx.StringData(entry.CompromisedState),
		"passwordState":    llx.StringData(entry.PasswordState),
		"languageCode":     llx.StringData(entry.LanguageCode),
		"userAgent":        llx.StringData(entry.UserAgent),
		"createTime":       llx.TimeDataPtr(parseRFC3339(entry.CreateTime)),
		"firstSyncTime":    llx.TimeDataPtr(parseRFC3339(entry.FirstSyncTime)),
		"lastSyncTime":     llx.TimeDataPtr(parseRFC3339(entry.LastSyncTime)),
	})
}

func (g *mqlGoogleworkspaceEndpointUser) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "googleworkspace.endpoint.user/" + g.Id.Data, nil
}
