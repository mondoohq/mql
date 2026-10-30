// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows
// +build windows

package windows

import (
	"errors"
	"runtime"
	"strconv"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/wmiquery"
)

const wmiOSQuery = "SELECT Name, Caption, Manufacturer, OSArchitecture, Version, BuildNumber, Description, OSType, ProductType, SerialNumber FROM Win32_OperatingSystem"

func GetWmiInformation(conn shared.Connection) (*WmicOSInformation, error) {
	// if we are running locally on windows, we want to avoid using powershell to be faster
	if conn.Type() == shared.Type_Local && runtime.GOOS == "windows" {

		// on an error, or a panic in WMI, fall back to PowerShell instead of
		// failing detection
		entries, err := wmiquery.Query(wmiOSQuery, "Name", "Caption", "Manufacturer", "OSArchitecture",
			"Version", "BuildNumber", "Description", "OSType", "ProductType", "SerialNumber")
		if err != nil {
			log.Debug().Err(err).Msg("could not query the OS via WMI, falling back to PowerShell")
			return powershellGetWmiInformation(conn)
		}

		if len(entries) != 1 || entries[0].StringPtr("Version") == nil {
			return nil, errors.New("could not query machine id on windows")
		}

		entry := entries[0]
		return &WmicOSInformation{
			Name:           entry.String("Name"),
			Caption:        entry.String("Caption"),
			Manufacturer:   entry.String("Manufacturer"),
			OSArchitecture: entry.String("OSArchitecture"),
			Version:        entry.String("Version"),
			BuildNumber:    entry.String("BuildNumber"),
			Description:    entry.String("Description"),
			OSType:         intToString(entry, "OSType"),
			ProductType:    intToString(entry, "ProductType"),
			SerialNumber:   entry.String("SerialNumber"),
		}, nil
	}

	return powershellGetWmiInformation(conn)
}

// intToString formats an integer property, or "" when it is NULL.
func intToString(entry wmiquery.Row, name string) string {
	i, ok := entry.Int64(name)
	if !ok {
		return ""
	}
	return strconv.FormatInt(i, 10)
}
