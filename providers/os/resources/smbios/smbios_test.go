// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package smbios

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/detector"
)

// resetManagerCache clears the entire manager cache. Intended for use in tests
// where mock connections share the same ID across different test cases.
func resetManagerCache() {
	managerCache.Range(func(key, _ any) bool {
		managerCache.Delete(key)
		return true
	})
}

func Test_WindowsSmbiosChassis_AdHoc(t *testing.T) {
	// First two are real-life examples, others are augmented test cases
	data := `
{
  "Chassis": [
    {
      "Manufacturer": "Redacted",
      "Model": null,
      "LockPresent": "False",
      "SerialNumber": "R3D4CT3D",
      "SMBIOSAssetTag": "none",
      "SecurityStatus": "2",
      "ChassisTypes": [1]
    },
    {
      "Manufacturer": "Redacted",
      "Model": null,
      "LockPresent": "False",
      "SerialNumber": "R3D4CT3D",
      "SMBIOSAssetTag": "SomeTag_77",
      "SecurityStatus": "2",
			"ChassisTypes": "unknown"
    },
		{
      "Manufacturer": "Redacted",
      "Model": null,
      "LockPresent": "False",
      "SerialNumber": "R3D4CT3D",
      "SMBIOSAssetTag": "none",
      "SecurityStatus": "2",
			"ChassisTypes": ["1"]
    },
    {
      "Manufacturer": "Redacted",
      "Model": null,
      "LockPresent": "False",
      "SerialNumber": "R3D4CT3D",
      "SMBIOSAssetTag": "SomeTag_77",
      "SecurityStatus": "2",
			"ChassisTypes": null
		},
    {
      "Manufacturer": "Redacted",
      "Model": null,
      "LockPresent": "False",
      "SerialNumber": "R3D4CT3D",
      "SMBIOSAssetTag": "SomeTag_77",
      "SecurityStatus": "2",
			"ChassisTypes": [null]
    }
  ]
}
`

	dataReader := strings.NewReader(data)

	smi, err := ParseWindowsSmbiosInfo(dataReader)
	require.NoError(t, err)

	chassis := smi.Chassis
	require.Len(t, chassis, 5)

	require.Equal(t, []string{"1"}, chassis[0].GetChassisTypes().Value())
	require.Equal(t, []string{"unknown"}, chassis[1].GetChassisTypes().Value())
	require.Equal(t, []string{"1"}, chassis[2].GetChassisTypes().Value())
	require.Equal(t, []string{""}, chassis[3].GetChassisTypes().Value())
	require.Equal(t, []string{""}, chassis[4].GetChassisTypes().Value())
}

func TestManagerUnixFamily(t *testing.T) {
	t.Cleanup(resetManagerCache)
	// special case where we detect a unix system other than darwin
	// use centos and change the platform family
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/centos.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)
	platform.Family = []string{"unix"}

	mm, err := ResolveManager(conn, platform)
	require.NoError(t, err)
	biosInfo, err := mm.Info()
	require.NoError(t, err)
	assert.Equal(t, &SmBiosInfo{
		BIOS: BiosInfo{
			Vendor:      "innotek GmbH",
			Version:     "VirtualBox",
			ReleaseDate: "12/01/2006",
		},
		SysInfo: SysInfo{
			Vendor:       "innotek GmbH",
			Model:        "VirtualBox",
			Version:      "1.2",
			SerialNumber: "0",
			UUID:         "64f118d3-0060-4a4c-bf1f-a11d655c4d6f",
			Family:       "Virtual Machine",
			SKU:          "",
		},
		BaseBoardInfo: BaseBoardInfo{
			Vendor:       "Oracle Corporation",
			Model:        "VirtualBox",
			Version:      "1.2",
			SerialNumber: "0",
			AssetTag:     "",
		},
		ChassisInfo: ChassisInfo{
			Vendor:       "Oracle Corporation",
			Model:        "",
			Version:      "",
			SerialNumber: "",
			AssetTag:     "",
			Type:         "1",
		},
	}, biosInfo)
}

func TestManagerCentos(t *testing.T) {
	t.Cleanup(resetManagerCache)
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/centos.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	mm, err := ResolveManager(conn, platform)
	require.NoError(t, err)
	biosInfo, err := mm.Info()
	require.NoError(t, err)
	assert.Equal(t, &SmBiosInfo{
		BIOS: BiosInfo{
			Vendor:      "innotek GmbH",
			Version:     "VirtualBox",
			ReleaseDate: "12/01/2006",
		},
		SysInfo: SysInfo{
			Vendor:       "innotek GmbH",
			Model:        "VirtualBox",
			Version:      "1.2",
			SerialNumber: "0",
			UUID:         "64f118d3-0060-4a4c-bf1f-a11d655c4d6f",
			Family:       "Virtual Machine",
			SKU:          "",
		},
		BaseBoardInfo: BaseBoardInfo{
			Vendor:       "Oracle Corporation",
			Model:        "VirtualBox",
			Version:      "1.2",
			SerialNumber: "0",
			AssetTag:     "",
		},
		ChassisInfo: ChassisInfo{
			Vendor:       "Oracle Corporation",
			Model:        "",
			Version:      "",
			SerialNumber: "",
			AssetTag:     "",
			Type:         "1",
		},
	}, biosInfo)
}

func TestManagerMacos(t *testing.T) {
	t.Cleanup(resetManagerCache)
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/macos.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	mm, err := ResolveManager(conn, platform)
	require.NoError(t, err)
	biosInfo, err := mm.Info()
	require.NoError(t, err)
	assert.Equal(t, &SmBiosInfo{
		BIOS: BiosInfo{
			Vendor:      "Apple Inc.",
			Version:     "170.0.0.0.0",
			ReleaseDate: "06/17/2019",
		},
		SysInfo: SysInfo{
			Vendor:       "Apple Inc.",
			Model:        "iMac17,1",
			Version:      "1.0",
			SerialNumber: "DAAAA111AA11",
			UUID:         "e126775d-2368-4f51-9863-76d5df0c8108",
			Family:       "",
			SKU:          "",
		},
		BaseBoardInfo: BaseBoardInfo{
			Vendor:       "Apple Inc.",
			Model:        "Mac-A111A1117AA1AA1A",
			Version:      "",
			SerialNumber: "DAAAA111AA11",
			AssetTag:     "",
		},
		ChassisInfo: ChassisInfo{
			Vendor:       "Apple Inc.",
			Model:        "",
			Version:      "Mac-A111A1117AA1AA1A",
			SerialNumber: "DAAAA111AA11",
			AssetTag:     "",
			Type:         "Laptop",
		},
	}, biosInfo)
}

func TestManagerWindows(t *testing.T) {
	t.Cleanup(resetManagerCache)
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/windows.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	mm, err := ResolveManager(conn, platform)
	require.NoError(t, err)
	biosInfo, err := mm.Info()
	require.NoError(t, err)
	assert.Equal(t, &SmBiosInfo{
		BIOS: BiosInfo{
			Vendor:      "VMware, Inc.",
			Version:     "VMW71.00V.16722896.B64.2008100651",
			ReleaseDate: "2020-08-10T00:00:00Z",
		},
		SysInfo: SysInfo{
			Vendor:       "VMware, Inc.",
			Model:        "VMware7,1",
			Version:      "None",
			SerialNumber: "VMware-56 4d bd 16 98 6b f9 23-49 3c f6 b1 4e 7c fc 0b",
			UUID:         "16BD4D56-6B98-23F9-493C-F6B14E7CFC0B",
			Family:       "",
			SKU:          "",
		},
		BaseBoardInfo: BaseBoardInfo{
			Vendor:       "Intel Corporation",
			Model:        "440BX Desktop Reference Platform",
			Version:      "None",
			SerialNumber: "None",
			AssetTag:     "",
		},
		ChassisInfo: ChassisInfo{
			Vendor:       "No Enclosure",
			Model:        "",
			Version:      "N/A",
			SerialNumber: "None",
			AssetTag:     "No Asset Tag",
			Type:         "1",
		},
	}, biosInfo)
}

func TestManagerAIX(t *testing.T) {
	t.Cleanup(resetManagerCache)
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/aix.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	mm, err := ResolveManager(conn, platform)
	require.NoError(t, err)
	biosInfo, err := mm.Info()
	require.NoError(t, err)
	assert.Equal(t, &SmBiosInfo{
		SysInfo: SysInfo{
			Vendor:       "IBM",
			Model:        "IBM,9009-22A",
			Version:      "IBM,FW950.D0 (VL950_175)",
			SerialNumber: "7835450",
			Family:       "IBM Power Systems",
		},
		BaseBoardInfo: BaseBoardInfo{
			Vendor:       "IBM",
			Model:        "IBM,9009-22A",
			Version:      "IBM,FW950.D0 (VL950_175)",
			SerialNumber: "7835450",
		},
	}, biosInfo)
}
