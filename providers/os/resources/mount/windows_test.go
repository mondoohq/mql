// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mount_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/mount"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

func windowsAsset() *inventory.Asset {
	return &inventory.Asset{
		Platform: &inventory.Platform{Name: "windows", Family: []string{"windows", "os"}},
	}
}

func windowsVolumeMock(t *testing.T, stdout string, exit int) *mock.Connection {
	t.Helper()
	conn, err := mock.New(0, windowsAsset(), mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			powershell.Encode(windows.VolumesScript): {Stdout: stdout, ExitStatus: exit},
		},
	}))
	require.NoError(t, err)
	return conn
}

func TestWindowsManagerLists(t *testing.T) {
	data, err := os.ReadFile("../windows/testdata/volumes-ws2022.json")
	require.NoError(t, err)

	mm, err := mount.ResolveManager(windowsVolumeMock(t, string(data), 0))
	require.NoError(t, err)
	mounts, err := mm.List()
	require.NoError(t, err)

	byPath := map[string]mount.MountPoint{}
	for _, m := range mounts {
		byPath[m.MountPoint] = m
	}
	require.Len(t, byPath, 3)

	c, ok := byPath[`C:\`]
	require.True(t, ok)
	assert.Equal(t, `\\?\Volume{01cef182-0000-0000-0000-100000000000}\`, c.Device)
	assert.Equal(t, "NTFS", c.FSType)
	assert.False(t, c.Unmounted)
	require.NotNil(t, c.Usage)
	assert.Equal(t, int64(64422408192), c.Usage.Size)
	assert.Equal(t, int64(42523316224), c.Usage.Available)
	assert.Equal(t, int64(64422408192-42523316224), c.Usage.Used)
	assert.Equal(t, map[string]string{
		"driveType": "Fixed", "bootVolume": "", "systemVolume": "", "pageFile": "",
	}, c.Options)

	e := byPath[`E:\`]
	assert.Equal(t, map[string]string{"driveType": "Fixed", "label": "MQLDATA"}, e.Options)

	folder, ok := byPath[`C:\mnt\data`]
	require.True(t, ok, "the folder-mounted volume must be listed at its folder")
	assert.Equal(t, `\\?\Volume{d24a16dc-fc72-48eb-9637-69658f6281c7}\`, folder.Device)
	require.NotNil(t, folder.Usage)
	assert.Equal(t, int64(6424621056), folder.Usage.Size)
}

func TestWindowsMountPointsPerAccessPath(t *testing.T) {
	capacity, free := int64(1000), int64(250)
	mounts := mount.WindowsMountPoints([]windows.Volume{
		{
			DeviceID: `\\?\Volume{aaaa}\`, AccessPaths: []string{`C:\mnt\e`, `E:\`},
			FileSystem: "NTFS", DriveType: "Fixed", Capacity: &capacity, FreeSpace: &free, Compressed: true,
		},
		{DeviceID: `\\?\Volume{cccc}\`, AccessPaths: []string{`D:\`}, DriveType: "CDRom"},
	})
	require.Len(t, mounts, 3)

	assert.Equal(t, `C:\mnt\e`, mounts[0].MountPoint)
	assert.Equal(t, `E:\`, mounts[1].MountPoint)
	for _, m := range mounts[:2] {
		assert.Equal(t, `\\?\Volume{aaaa}\`, m.Device)
		require.NotNil(t, m.Usage)
		assert.Equal(t, int64(750), m.Usage.Used)
		assert.Equal(t, int64(250), m.Usage.Available)
		assert.Contains(t, m.Options, "compressed")
		assert.False(t, m.Unmounted)
	}
	// Separate maps: changing one mount's options must not change another's.
	mounts[0].Options["x"] = "y"
	assert.NotContains(t, mounts[1].Options, "x")

	// An empty optical drive: a drive letter with nothing mounted behind it,
	// and no capacity rather than a capacity of zero.
	d := mounts[2]
	assert.True(t, d.Unmounted)
	assert.Nil(t, d.Usage)
	assert.Equal(t, "", d.FSType)
	assert.Equal(t, "CDRom", d.Options["driveType"])
}

func TestWindowsManagerFailedScriptIsAnError(t *testing.T) {
	mm, err := mount.ResolveManager(windowsVolumeMock(t, "", 0))
	require.NoError(t, err)
	_, err = mm.List()
	require.Error(t, err, "an empty answer must not read as no volumes")
}

// noCommands is a Windows connection that cannot run anything: an image or a
// mounted disk.
type noCommands struct {
	*mock.Connection
}

func (noCommands) Capabilities() shared.Capabilities {
	return shared.Capability_File
}

func TestWindowsManagerWithoutCommandsIsNotApplicable(t *testing.T) {
	conn, err := mock.New(0, windowsAsset())
	require.NoError(t, err)

	mm, err := mount.ResolveManager(noCommands{conn})
	require.NoError(t, err)
	_, err = mm.List()
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(err))
}
