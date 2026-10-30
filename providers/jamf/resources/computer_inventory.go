// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/url"
	"strconv"
	"time"

	"github.com/deploymenttheory/go-api-sdk-jamfpro/sdk/jamfpro"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/jamf/connection"
)

// parseJamfTime parses a Jamf Pro API date string (ISO 8601 / RFC 3339).
// Returns nil if the string is empty or unparseable.
func parseJamfTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

// inventorySections lists the Jamf inventory sections we expose. Without
// this filter the API returns every section per record (applications,
// certificates, configuration profiles, fonts, group memberships, package
// receipts, software updates, …) — payloads that are routinely 100x the
// data we use.
var inventorySections = []string{
	"GENERAL",
	"HARDWARE",
	"OPERATING_SYSTEM",
	"SECURITY",
	"LOCAL_USER_ACCOUNTS",
}

// inventoryPageSize is the per-request page size. The SDK defaults to 100;
// Jamf Pro allows up to 2000. 500 cuts round-trip count 5x compared to the
// default while keeping per-request payload size manageable.
const inventoryPageSize = 500

func (r *mqlJamf) computerInventory() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.JamfConnection)
	client := conn.Client

	// The SDK's GetComputersInventory paginates through all pages internally,
	// so a single call returns every inventory record.
	params := url.Values{}
	for _, s := range inventorySections {
		params.Add("section", s)
	}
	params.Set("page-size", strconv.Itoa(inventoryPageSize))
	inventory, err := client.GetComputersInventory(params)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(inventory.Results))
	for _, c := range inventory.Results {
		conn.CacheLocalUserAccounts(c.ID, c.LocalUserAccounts)

		item, err := CreateResource(r.MqlRuntime, "jamf.computer", map[string]*llx.RawData{
			"id":                                   llx.StringData(c.ID),
			"name":                                 llx.StringData(c.General.Name),
			"make":                                 llx.StringData(c.Hardware.Make),
			"model":                                llx.StringData(c.Hardware.Model),
			"modelIdentifier":                      llx.StringData(c.Hardware.ModelIdentifier),
			"operatingSystemName":                  llx.StringData(c.OperatingSystem.Name),
			"operatingSystemVersion":               llx.StringData(c.OperatingSystem.Version),
			"build":                                llx.StringData(c.OperatingSystem.Build),
			"macAddress":                           llx.StringData(c.Hardware.MacAddress),
			"serialNumber":                         llx.StringData(c.Hardware.SerialNumber),
			"processorType":                        llx.StringData(c.Hardware.ProcessorType),
			"processorArchitecture":                llx.StringData(c.Hardware.ProcessorArchitecture),
			"processorCount":                       llx.IntData(c.Hardware.ProcessorCount),
			"coreCount":                            llx.IntData(c.Hardware.CoreCount),
			"totalRamMegabytes":                    llx.IntData(c.Hardware.TotalRamMegabytes),
			"lastIpAddress":                        llx.StringData(c.General.LastIpAddress),
			"lastReportedIp":                       llx.StringData(c.General.LastReportedIp),
			"jamfBinaryVersion":                    llx.StringData(c.General.JamfBinaryVersion),
			"assetTag":                             llx.StringData(c.General.AssetTag),
			"platform":                             llx.StringData(c.General.Platform),
			"reportDate":                           llx.TimeDataPtr(parseJamfTime(c.General.ReportDate)),
			"lastContactTime":                      llx.TimeDataPtr(parseJamfTime(c.General.LastContactTime)),
			"lastEnrolledDate":                     llx.TimeDataPtr(parseJamfTime(c.General.LastEnrolledDate)),
			"initialEntryDate":                     llx.TimeDataPtr(parseJamfTime(c.General.InitialEntryDate)),
			"itunesStoreAccountActive":             llx.BoolData(c.General.ItunesStoreAccountActive),
			"enrolledViaAutomatedDeviceEnrollment": llx.BoolData(c.General.EnrolledViaAutomatedDeviceEnrollment),
			"fileVault2Status":                     llx.StringData(c.OperatingSystem.FileVault2Status),
			"autoLoginDisabled":                    llx.BoolData(c.Security.AutoLoginDisabled),
			"activationLockEnabled":                llx.BoolData(c.Security.ActivationLockEnabled),
			"firewallEnabled":                      llx.BoolData(c.Security.FirewallEnabled),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, item)
	}
	return res, nil
}

func (c *mqlJamfComputer) id() (string, error) {
	return "jamf.computer/" + c.Id.Data, nil
}

func (c *mqlJamfComputer) localUserAccounts() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.JamfConnection)

	if cached, ok := conn.GetCachedLocalUserAccounts(c.Id.Data); ok {
		return createLocalUserAccountResources(c.MqlRuntime, c.Id.Data, cached)
	}

	// Fallback path: the computer was constructed outside of
	// jamf.computerInventory (e.g. a recording replay). Populate the cache so
	// repeat accesses don't re-fetch.
	inventory, err := conn.Client.GetComputerInventoryByID(c.Id.Data)
	if err != nil {
		return nil, err
	}
	conn.CacheLocalUserAccounts(c.Id.Data, inventory.LocalUserAccounts)
	return createLocalUserAccountResources(c.MqlRuntime, c.Id.Data, inventory.LocalUserAccounts)
}

func createLocalUserAccountResources(runtime *plugin.Runtime, computerID string, accounts []jamfpro.ComputerInventorySubsetLocalUserAccount) ([]any, error) {
	var res []any
	for _, user := range accounts {
		item, err := CreateResource(runtime, "jamf.localUserAccount", map[string]*llx.RawData{
			"__id":                         llx.StringData("jamf.localUserAccount/" + computerID + "/" + user.UID + "/" + user.Username),
			"uid":                          llx.StringData(user.UID),
			"username":                     llx.StringData(user.Username),
			"fullName":                     llx.StringData(user.FullName),
			"admin":                        llx.BoolData(user.Admin),
			"fileVault2Enabled":            llx.BoolData(user.FileVault2Enabled),
			"userAccountType":              llx.StringData(user.UserAccountType),
			"passwordMaxAge":               llx.IntData(int64(user.PasswordMaxAge)),
			"homeDirectory":                llx.StringData(user.HomeDirectory),
			"passwordMinLength":            llx.IntData(int64(user.PasswordMinLength)),
			"passwordMinComplexCharacters": llx.IntData(int64(user.PasswordMinComplexCharacters)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, item)
	}
	return res, nil
}
