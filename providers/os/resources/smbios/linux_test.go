// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package smbios

import (
	"os"
	"syscall"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// denyFs refuses to open the named paths with EACCES, the way sysfs refuses a
// non-root reader on the DMI attributes the kernel marks root-only.
type denyFs struct {
	afero.Fs
	deny map[string]bool
}

func (f *denyFs) Open(name string) (afero.File, error) {
	if f.deny[name] {
		return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EACCES}
	}
	return f.Fs.Open(name)
}

// dmiFs builds a /sys/class/dmi/id tree with the attribute set a real host
// exports.
func dmiFs(t *testing.T) afero.Fs {
	t.Helper()

	fs := afero.NewMemMapFs()
	for name, content := range map[string]string{
		"bios_date":         "04/01/2014\n",
		"bios_vendor":       "SeaBIOS\n",
		"bios_version":      "1.16.3-2.fc39\n",
		"board_asset_tag":   "board-tag\n",
		"board_name":        "board-name\n",
		"board_serial":      "board-secret\n",
		"board_vendor":      "board-vendor\n",
		"board_version":     "board-version\n",
		"chassis_asset_tag": "chassis-tag\n",
		"chassis_serial":    "chassis-secret\n",
		"chassis_type":      "1\n",
		"chassis_vendor":    "QEMU\n",
		"chassis_version":   "pc-q35\n",
		"product_family":    "Unknown\n",
		"product_name":      "Standard PC (Q35 + ICH9, 2009)\n",
		"product_serial":    "product-secret\n",
		"product_sku":       "sku-1\n",
		"product_uuid":      "1a2b3c4d-0000-0000-0000-000000000000\n",
		"product_version":   "pc-q35-8.1\n",
		"sys_vendor":        "QEMU\n",
	} {
		require.NoError(t, afero.WriteFile(fs, dmiRoot+name, []byte(content), 0o444))
	}
	return fs
}

func TestLinuxSmbios_AllAttributesReadable(t *testing.T) {
	info, err := readLinuxSmbios(dmiFs(t))
	require.NoError(t, err)

	assert.Equal(t, "SeaBIOS", info.BIOS.Vendor)
	assert.Equal(t, "1.16.3-2.fc39", info.BIOS.Version)
	assert.Equal(t, "04/01/2014", info.BIOS.ReleaseDate)
	assert.Equal(t, "QEMU", info.SysInfo.Vendor)
	assert.Equal(t, "Standard PC (Q35 + ICH9, 2009)", info.SysInfo.Model)
	assert.Equal(t, "product-secret", info.SysInfo.SerialNumber)
	assert.Equal(t, "1a2b3c4d-0000-0000-0000-000000000000", info.SysInfo.UUID)
	assert.Equal(t, "board-secret", info.BaseBoardInfo.SerialNumber)
	assert.Equal(t, "chassis-secret", info.ChassisInfo.SerialNumber)
	assert.Equal(t, "1", info.ChassisInfo.Type)
}

// The kernel marks product_serial, board_serial, chassis_serial and
// product_uuid as root-only (mode 0400), so every scan that does not run as
// root gets EACCES on those four and on nothing else. Before the fix the walk
// returned that error, so the whole SMBIOS read failed and machine.bios,
// machine.system, machine.baseboard and machine.chassis all reported no data.
func TestLinuxSmbios_KeepsReadableAttributesWhenSerialsAreRootOnly(t *testing.T) {
	fs := &denyFs{
		Fs: dmiFs(t),
		deny: map[string]bool{
			dmiRoot + "product_serial": true,
			dmiRoot + "board_serial":   true,
			dmiRoot + "chassis_serial": true,
			dmiRoot + "product_uuid":   true,
		},
	}

	info, err := readLinuxSmbios(fs)
	require.NoError(t, err)

	// the readable attributes still arrive, including the ones that sort
	// after the denied entries
	assert.Equal(t, "SeaBIOS", info.BIOS.Vendor)
	assert.Equal(t, "1.16.3-2.fc39", info.BIOS.Version)
	assert.Equal(t, "04/01/2014", info.BIOS.ReleaseDate)
	assert.Equal(t, "board-name", info.BaseBoardInfo.Model)
	assert.Equal(t, "board-vendor", info.BaseBoardInfo.Vendor)
	assert.Equal(t, "chassis-tag", info.ChassisInfo.AssetTag)
	assert.Equal(t, "1", info.ChassisInfo.Type)
	assert.Equal(t, "QEMU", info.ChassisInfo.Vendor)
	assert.Equal(t, "Standard PC (Q35 + ICH9, 2009)", info.SysInfo.Model)
	assert.Equal(t, "sku-1", info.SysInfo.SKU)
	assert.Equal(t, "pc-q35-8.1", info.SysInfo.Version)
	assert.Equal(t, "QEMU", info.SysInfo.Vendor)

	// the four we could not read stay empty rather than carrying a value we
	// never saw
	assert.Empty(t, info.SysInfo.SerialNumber)
	assert.Empty(t, info.SysInfo.UUID)
	assert.Empty(t, info.BaseBoardInfo.SerialNumber)
	assert.Empty(t, info.ChassisInfo.SerialNumber)
}

// A host with no DMI tables at all reports an empty struct, not an error.
func TestLinuxSmbios_NoDmiDirectory(t *testing.T) {
	info, err := readLinuxSmbios(afero.NewMemMapFs())
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Empty(t, info.BIOS.Vendor)
}
