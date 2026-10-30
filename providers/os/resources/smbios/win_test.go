// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package smbios

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Shape of smbiosWindowsScript's output under Windows PowerShell 5.1 over WinRM
// on Windows 10 22H2 and Windows 11 25H2 Hyper-V guests, trimmed to the
// decoded properties; serials replaced.
const windowsPS51SmbiosJSON = `{
  "Bios": {
    "Manufacturer": "Microsoft Corporation",
    "SMBIOSBIOSVersion": "Hyper-V UEFI Release v4.1",
    "ReleaseDate": "\/Date(1767830400000)\/",
    "SerialNumber": "1111-2222-3333-4444-5555-6666-77"
  },
  "BaseBoard": {
    "Manufacturer": "Microsoft Corporation",
    "Product": "Virtual Machine",
    "Version": "Hyper-V UEFI Release v4.1",
    "SerialNumber": "2222-3333-4444-5555-6666-7777-88"
  },
  "Chassis": [
    {
      "Manufacturer": "Microsoft Corporation",
      "Model": null,
      "ChassisTypes": [3],
      "Version": "Hyper-V UEFI Release v4.1",
      "SerialNumber": "3333-4444-5555-6666-7777-8888-99",
      "SMBIOSAssetTag": "4444-5555-6666-7777-8888-9999-00"
    }
  ],
  "System": {
    "SystemFamily": "Virtual Machine"
  },
  "SystemProduct": {
    "Vendor": "Microsoft Corporation",
    "Name": "Virtual Machine",
    "Version": "Hyper-V UEFI Release v4.1",
    "SKUNumber": null,
    "UUID": "00000000-1111-2222-3333-444444444444",
    "IdentifyingNumber": "0000-1111-2222-3333-4444-5555-66"
  }
}`

func TestWindowsSmbiosToSmBiosInfo(t *testing.T) {
	winBios, err := ParseWindowsSmbiosInfo(strings.NewReader(windowsPS51SmbiosJSON))
	require.NoError(t, err)

	assert.Equal(t, &SmBiosInfo{
		BIOS: BiosInfo{
			Vendor:      "Microsoft Corporation",
			Version:     "Hyper-V UEFI Release v4.1",
			ReleaseDate: "2026-01-08T00:00:00Z",
		},
		SysInfo: SysInfo{
			Vendor:       "Microsoft Corporation",
			Model:        "Virtual Machine",
			Version:      "Hyper-V UEFI Release v4.1",
			SerialNumber: "0000-1111-2222-3333-4444-5555-66",
			UUID:         "00000000-1111-2222-3333-444444444444",
			Family:       "Virtual Machine",
			SKU:          "",
		},
		BaseBoardInfo: BaseBoardInfo{
			Vendor:       "Microsoft Corporation",
			Model:        "Virtual Machine",
			Version:      "Hyper-V UEFI Release v4.1",
			SerialNumber: "2222-3333-4444-5555-6666-7777-88",
		},
		ChassisInfo: ChassisInfo{
			Vendor:       "Microsoft Corporation",
			Model:        "",
			Version:      "Hyper-V UEFI Release v4.1",
			SerialNumber: "3333-4444-5555-6666-7777-8888-99",
			AssetTag:     "4444-5555-6666-7777-8888-9999-00",
			Type:         "3",
		},
	}, winBios.toSmBiosInfo())
}

func TestWindowsSmbiosToSmBiosInfoNoChassis(t *testing.T) {
	info := smbiosWindows{}.toSmBiosInfo()
	assert.Equal(t, ChassisInfo{}, info.ChassisInfo)
}

func TestWindowsBiosReleaseDate(t *testing.T) {
	cases := map[string]string{
		// Windows PowerShell 5.1 ConvertTo-Json of a CIM DateTime
		"/Date(1767830400000)/": "2026-01-08T00:00:00Z",
		// the variant that carries the zone the value was local to
		"/Date(1767830400000+0100)/": "2026-01-08T00:00:00Z",
		// raw CIM_DATETIME, as Get-WmiObject sends it
		"20200810000000.000000+000": "2020-08-10T00:00:00Z",
		"20200810000000.000000+060": "2020-08-09T23:00:00Z",
		// PowerShell 7 writes ISO 8601
		"2026-01-08T00:00:00.0000000+00:00": "2026-01-08T00:00:00Z",
		"not a date":                        "not a date",
		"":                                  "",
	}
	for in, want := range cases {
		assert.Equal(t, want, windowsBiosReleaseDate(in), in)
	}
}

// The native WMI path formats through the same helper; a datetime read with a
// non-zero offset must land on the same string as the /Date(ms)/ PowerShell path.
func TestFormatBiosReleaseDateMatchesPowershellPath(t *testing.T) {
	native := formatBiosReleaseDate(time.Date(2026, 1, 8, 1, 0, 0, 0, time.FixedZone("", 60*60)))
	assert.Equal(t, windowsBiosReleaseDate("/Date(1767830400000)/"), native)
}
