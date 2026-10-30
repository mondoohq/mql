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

func TestManagerFreeBSD(t *testing.T) {
	t.Cleanup(resetManagerCache)
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/freebsd.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)
	require.Equal(t, "freebsd", platform.Name)

	mm, err := ResolveManager(conn, platform)
	require.NoError(t, err)
	assert.Equal(t, "FreeBSD Smbios Manager", mm.Name())

	biosInfo, err := mm.Info()
	require.NoError(t, err)
	assert.Equal(t, &SmBiosInfo{
		BIOS: BiosInfo{
			Vendor:      "Amazon EC2",
			Version:     "1.0",
			ReleaseDate: "10/16/2017",
		},
		SysInfo: SysInfo{
			Vendor:       "Amazon EC2",
			Model:        "t3.medium",
			SerialNumber: "ec2aaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			UUID:         "ec2aaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		},
		BaseBoardInfo: BaseBoardInfo{
			Vendor:   "Amazon EC2",
			AssetTag: "i-0123456789abcdef0",
		},
		ChassisInfo: ChassisInfo{
			Vendor:   "Amazon EC2",
			AssetTag: "Amazon EC2",
			Type:     "Other",
		},
	}, biosInfo)
}

// The cloud detectors read the same SmBiosInfo fields on every non-Linux
// platform: GCP matches SysInfo.Model, Azure/VMware/Hetzner/IBM match
// SysInfo.Vendor, AWS matches BIOS.Vendor. These values are the SMBIOS strings
// those clouds publish, as the FreeBSD loader would expose them.
func TestParseKenvSmbios_OtherClouds(t *testing.T) {
	t.Run("gce", func(t *testing.T) {
		info, err := ParseKenvSmbios(strings.NewReader(`smbios.bios.vendor="Google"
smbios.system.maker="Google"
smbios.system.product="Google Compute Engine"
`))
		require.NoError(t, err)
		assert.Equal(t, "Google Compute Engine", info.SysInfo.Model)
		assert.Equal(t, "Google", info.SysInfo.Vendor)
	})
	t.Run("azure", func(t *testing.T) {
		info, err := ParseKenvSmbios(strings.NewReader(`smbios.system.maker="Microsoft Corporation"
smbios.system.product="Virtual Machine"
smbios.system.version="7.0"
`))
		require.NoError(t, err)
		assert.Equal(t, "Microsoft Corporation", info.SysInfo.Vendor)
		assert.Equal(t, "Virtual Machine", info.SysInfo.Model)
		assert.Equal(t, "7.0", info.SysInfo.Version)
	})
}

func TestParseKenvSmbios_Edges(t *testing.T) {
	info, err := ParseKenvSmbios(strings.NewReader(`not a kenv line
hint.smbios.0.mem="0xbbe6a000"
smbios.system.product="Model=X \"special\""
smbios.system.sku=""
smbios.planar.product=unquoted
`))
	require.NoError(t, err)
	// hint.smbios.* is a device hint, not an SMBIOS string
	assert.Equal(t, BiosInfo{}, info.BIOS)
	// only the first '=' separates name from value
	assert.Equal(t, `Model=X \"special\"`, info.SysInfo.Model)
	assert.Equal(t, "", info.SysInfo.SKU)
	assert.Equal(t, "unquoted", info.BaseBoardInfo.Model)
}

func TestParseKenvSmbios_Empty(t *testing.T) {
	// a machine without SMBIOS (e.g. arm64 without firmware tables) has no
	// smbios.* variables at all
	info, err := ParseKenvSmbios(strings.NewReader("kernel=\"kernel\"\n"))
	require.NoError(t, err)
	assert.Equal(t, &SmBiosInfo{}, info)
}
