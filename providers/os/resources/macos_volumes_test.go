// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

func readMacosVolumesFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "macos-volumes", name))
	require.NoError(t, err)
	return data
}

// newMacosVolumesRuntime returns a runtime on a mock macOS connection that
// answers each diskutil command with its output from testdata. infoOverride
// replaces the `diskutil info` fixture of a device; an empty name leaves the
// device's command unanswered, which the mock reports as a failed command.
func newMacosVolumesRuntime(t *testing.T, pf *inventory.Platform, infoOverride map[string]string) *plugin.Runtime {
	t.Helper()
	commands := map[string]*mock.Command{
		"diskutil list -plist":      {Stdout: string(readMacosVolumesFixture(t, "list.plist"))},
		"diskutil apfs list -plist": {Stdout: string(readMacosVolumesFixture(t, "apfs-list.plist"))},
	}
	files, err := filepath.Glob(filepath.Join("testdata", "macos-volumes", "info-disk*s*.plist"))
	require.NoError(t, err)
	for _, f := range files {
		dev := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "info-"), ".plist")
		if strings.Contains(dev, "-") {
			continue
		}
		name := filepath.Base(f)
		if o, ok := infoOverride[dev]; ok {
			if o == "" {
				continue
			}
			name = o
		}
		commands["diskutil info -plist "+dev] = &mock.Command{Stdout: string(readMacosVolumesFixture(t, name))}
	}
	conn, err := mock.New(0, &inventory.Asset{Platform: pf}, mock.WithData(&mock.TomlData{Commands: commands}))
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

// macosVolumesFromFixtures runs macos.volumes on the mock connection and
// returns its volumes by device identifier, in list order.
func macosVolumesFromFixtures(t *testing.T, infoOverride map[string]string) (map[string]*mqlMacosVolume, []string) {
	t.Helper()
	res, err := CreateResource(newMacosVolumesRuntime(t, macosPlatform, infoOverride), "macos.volumes", nil)
	require.NoError(t, err)
	list := res.(*mqlMacosVolumes).GetList()
	require.NoError(t, list.Error)

	vols := map[string]*mqlMacosVolume{}
	ids := []string{}
	for _, r := range list.Data {
		v := r.(*mqlMacosVolume)
		vols[v.DeviceIdentifier.Data] = v
		ids = append(ids, v.DeviceIdentifier.Data)
	}
	return vols, ids
}

// Measured: MacBook Pro (Apple silicon), macOS 27.2 (26B123), FileVault on,
// 2026-11-02, with disk images attached: an APFS image (disk5s1), the same
// image's volume encrypted with `diskutil apfs encryptVolume` (disk10s1), and
// HFS+ (disk6s1), ExFAT (disk7s1), FAT (disk8s1) and journaled HFS+ (disk11s1)
// images. The fixtures are the unmodified `diskutil ... -plist` output, minus
// the SMART counters.
func TestParseDiskutilList(t *testing.T) {
	refs, err := parseDiskutilList(readMacosVolumesFixture(t, "list.plist"))
	require.NoError(t, err)

	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		ids = append(ids, r.deviceIdentifier)
	}
	// disk0s1-3, disk4s1 and disk9s1 are APFS physical stores; disk3s1s1 is
	// the sealed system snapshot mounted at /.
	assert.Equal(t, []string{
		"disk1s1", "disk1s2", "disk1s3", "disk1s4",
		"disk2s1", "disk2s2",
		"disk3s1", "disk3s2", "disk3s3", "disk3s4", "disk3s5", "disk3s6",
		"disk5s1", "disk6s1", "disk7s1", "disk8s1", "disk10s1", "disk11s1",
	}, ids)

	byID := map[string]diskutilVolumeRef{}
	for _, r := range refs {
		byID[r.deviceIdentifier] = r
	}
	assert.True(t, byID["disk3s5"].apfs)
	assert.Equal(t, "", byID["disk3s5"].partitionType)
	assert.False(t, byID["disk6s1"].apfs)
	assert.Equal(t, "Apple_HFS", byID["disk6s1"].partitionType)
	assert.Equal(t, "Windows_NTFS", byID["disk7s1"].partitionType)
	assert.Equal(t, "DOS_FAT_32", byID["disk8s1"].partitionType)
}

// Measured: same Mac and fixtures as TestParseDiskutilList.
func TestParseDiskutilAPFSRoles(t *testing.T) {
	roles, err := parseDiskutilAPFSRoles(readMacosVolumesFixture(t, "apfs-list.plist"))
	require.NoError(t, err)
	assert.Equal(t, []string{"System"}, roles["disk3s1"])
	assert.Equal(t, []string{"Data"}, roles["disk3s5"])
	assert.Equal(t, []string{"Preboot"}, roles["disk3s2"])
	assert.Equal(t, []string{"xART"}, roles["disk1s2"])
	assert.Empty(t, roles["disk10s1"])
	_, isAPFS := roles["disk6s1"]
	assert.False(t, isAPFS)
}

// Measured: same Mac and fixtures as TestParseDiskutilList; the expected
// values match a live `mql run local -c macos.volumes{*}` on that Mac.
func TestMacosVolumes(t *testing.T) {
	vols, ids := macosVolumesFromFixtures(t, nil)
	assert.Equal(t, []string{
		"disk1s1", "disk1s2", "disk1s3", "disk1s4",
		"disk2s1", "disk2s2",
		"disk3s1", "disk3s2", "disk3s3", "disk3s4", "disk3s5", "disk3s6",
		"disk5s1", "disk6s1", "disk7s1", "disk8s1", "disk10s1", "disk11s1",
	}, ids)

	data := vols["disk3s5"]
	assert.Equal(t, "Data", data.Name.Data)
	assert.Equal(t, "3FD5EBAE-82FF-4B32-97B0-C9ADD6F73A03", data.Uuid.Data)
	assert.Equal(t, "/System/Volumes/Data", data.MountPoint.Data)
	assert.Equal(t, "apfs", data.FilesystemType.Data)
	assert.Equal(t, "APFS", data.Filesystem.Data)
	assert.Equal(t, "", data.PartitionType.Data)
	assert.Equal(t, []any{"Data"}, data.Roles.Data)
	assert.Equal(t, "Apple Fabric", data.BusProtocol.Data)
	assert.True(t, data.Internal.Data)
	assert.False(t, data.OsInternal.Data)
	assert.True(t, data.Encrypted.Data)
	assert.True(t, data.FileVault.Data)
	assert.False(t, data.Locked.Data)
	assert.True(t, data.UserStorage.Data)

	system := vols["disk3s1"]
	assert.Equal(t, "Macintosh HD", system.Name.Data)
	assert.Equal(t, []any{"System"}, system.Roles.Data)
	assert.Equal(t, "", system.MountPoint.Data, "the sealed snapshot is mounted, not the volume")
	assert.True(t, system.FileVault.Data)
	assert.True(t, system.UserStorage.Data)

	for _, id := range []string{"disk3s2", "disk3s3", "disk3s6"} {
		assert.False(t, vols[id].OsInternal.Data, id)
		assert.False(t, vols[id].UserStorage.Data, id+" has a system role")
		assert.False(t, vols[id].FileVault.Data, id)
	}
	// Hidden from `diskutil list`: the iSC container, the Recovery container
	// and the Update volume.
	for _, id := range []string{"disk1s1", "disk1s2", "disk1s3", "disk1s4", "disk2s1", "disk2s2", "disk3s4"} {
		assert.True(t, vols[id].OsInternal.Data, id)
		assert.False(t, vols[id].UserStorage.Data, id)
	}

	plainAPFS := vols["disk5s1"]
	assert.False(t, plainAPFS.Internal.Data)
	assert.Equal(t, "Disk Image", plainAPFS.BusProtocol.Data)
	assert.Equal(t, []any{}, plainAPFS.Roles.Data)
	assert.False(t, plainAPFS.Encrypted.Data)
	assert.False(t, plainAPFS.FileVault.Data)
	assert.True(t, plainAPFS.UserStorage.Data)

	encAPFS := vols["disk10s1"]
	assert.False(t, encAPFS.Internal.Data)
	assert.True(t, encAPFS.Encrypted.Data)
	assert.True(t, encAPFS.FileVault.Data)
	assert.False(t, encAPFS.Locked.Data)
	assert.Equal(t, "/Volumes/CEPAPFSContainer", encAPFS.MountPoint.Data)

	// diskutil reports no FileVault, Encryption or Locked key for HFS+, ExFAT
	// and FAT volumes.
	hfs := vols["disk6s1"]
	assert.Equal(t, "hfs", hfs.FilesystemType.Data)
	assert.Equal(t, "HFS+", hfs.Filesystem.Data)
	assert.Equal(t, "Apple_HFS", hfs.PartitionType.Data)
	assert.Equal(t, []any{}, hfs.Roles.Data)
	assert.False(t, hfs.FileVault.Data)
	assert.False(t, hfs.Encrypted.Data)
	assert.True(t, hfs.UserStorage.Data)
	assert.Equal(t, "Journaled HFS+", vols["disk11s1"].Filesystem.Data)
	assert.Equal(t, "exfat", vols["disk7s1"].FilesystemType.Data)
	assert.Equal(t, "Windows_NTFS", vols["disk7s1"].PartitionType.Data)
	assert.Equal(t, "msdos", vols["disk8s1"].FilesystemType.Data)
	assert.Equal(t, "MS-DOS FAT16", vols["disk8s1"].Filesystem.Data)
}

// Measured: disk10s1 after `diskutil unmount`, which locks an encrypted APFS
// volume. diskutil list still names it, and info reports it locked.
func TestMacosVolumesLocked(t *testing.T) {
	vols, _ := macosVolumesFromFixtures(t, map[string]string{"disk10s1": "info-disk10s1-locked.plist"})
	locked := vols["disk10s1"]
	assert.True(t, locked.Locked.Data)
	assert.True(t, locked.FileVault.Data)
	assert.Equal(t, "", locked.MountPoint.Data)
	assert.Equal(t, "CEPAPFSContainer", locked.Name.Data)
}

// The volumes CIS macOS 5.3.1 and 5.3.2 assess, selected as the checks do.
// Measured: same Mac and fixtures as TestParseDiskutilList.
func TestMacosVolumesCISSelection(t *testing.T) {
	vols, _ := macosVolumesFromFixtures(t, nil)

	internalAPFS := map[string]bool{}
	externalAPFSOrHFS := map[string]bool{}
	for id, v := range vols {
		if !v.UserStorage.Data {
			continue
		}
		fs := v.FilesystemType.Data
		if v.Internal.Data && fs == "apfs" {
			internalAPFS[id] = v.FileVault.Data
		}
		if !v.Internal.Data && (fs == "apfs" || fs == "hfs") {
			externalAPFSOrHFS[id] = v.FileVault.Data
		}
	}
	// The CIS audit's example output: Macintosh HD and its Data volume.
	assert.Equal(t, map[string]bool{"disk3s1": true, "disk3s5": true}, internalAPFS)
	assert.Equal(t, map[string]bool{
		"disk5s1":  false,
		"disk6s1":  false,
		"disk10s1": true,
		"disk11s1": false,
	}, externalAPFSOrHFS)
}

// Synthetic: a volume diskutil cannot describe fails the list instead of
// shortening it, so an all() check cannot pass on a partial list.
func TestMacosVolumesInfoFails(t *testing.T) {
	runtime := newMacosVolumesRuntime(t, macosPlatform, map[string]string{"disk6s1": ""})
	res, err := CreateResource(runtime, "macos.volumes", nil)
	require.NoError(t, err)
	list := res.(*mqlMacosVolumes).GetList()
	require.Error(t, list.Error)
	assert.Contains(t, list.Error.Error(), "diskutil info -plist disk6s1 failed")
}

func TestMacosVolumesNotMacOS(t *testing.T) {
	linux := &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}
	_, err := NewResource(newMacosVolumesRuntime(t, linux, nil), "macos.volumes", nil)
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(err))
}

func TestMacosVolumeUserStorage(t *testing.T) {
	tests := []struct {
		name string
		vol  macosVolume
		want bool
	}{
		// Synthetic: an EFI system partition, which Disk Utility adds to
		// every GPT disk of 2 GB or more; no target showed this.
		{"EFI partition", macosVolume{partitionType: "EFI", filesystemType: "msdos"}, false},
		// Synthetic: the Recovery HD partition of an HFS+ system; no target showed this.
		{"Apple_Boot partition", macosVolume{partitionType: "Apple_Boot", filesystemType: "hfs"}, false},
		// Synthetic: a role this list does not know is assessed, not skipped.
		{"unknown role", macosVolume{roles: []string{"Backup"}, filesystemType: "apfs"}, true},
		{"system and data role", macosVolume{roles: []string{"System"}}, true},
		{"VM role", macosVolume{roles: []string{"VM"}}, false},
		{"no role", macosVolume{roles: []string{}}, true},
		{"OS internal without a role", macosVolume{osInternal: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.vol.userStorage())
		})
	}
}

// Synthetic: an HFS+ CoreStorage logical volume fills a whole disk of its
// own, with no partition map; its physical volume is an Apple_CoreStorage
// partition. No target showed this: macOS 27 cannot create CoreStorage
// volumes.
func TestParseDiskutilListWholeDiskFilesystem(t *testing.T) {
	data := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>AllDisksAndPartitions</key>
	<array>
		<dict>
			<key>Content</key><string>GUID_partition_scheme</string>
			<key>DeviceIdentifier</key><string>disk4</string>
			<key>Partitions</key>
			<array>
				<dict>
					<key>Content</key><string>EFI</string>
					<key>DeviceIdentifier</key><string>disk4s1</string>
					<key>VolumeName</key><string>EFI</string>
				</dict>
				<dict>
					<key>Content</key><string>Apple_CoreStorage</string>
					<key>DeviceIdentifier</key><string>disk4s2</string>
				</dict>
			</array>
		</dict>
		<dict>
			<key>Content</key><string>Apple_HFS</string>
			<key>DeviceIdentifier</key><string>disk5</string>
			<key>VolumeName</key><string>Backup</string>
		</dict>
		<dict>
			<key>Content</key><string>FDisk_partition_scheme</string>
			<key>DeviceIdentifier</key><string>disk6</string>
		</dict>
	</array>
</dict>
</plist>`)
	refs, err := parseDiskutilList(data)
	require.NoError(t, err)
	assert.Equal(t, []diskutilVolumeRef{
		{deviceIdentifier: "disk4s1", partitionType: "EFI"},
		{deviceIdentifier: "disk5"},
	}, refs)
}

// Synthetic: output that is not a plist must fail, not read as no volumes.
func TestParseDiskutilMalformed(t *testing.T) {
	_, err := parseDiskutilList([]byte("Could not find disk for -plist\n"))
	assert.Error(t, err)
	_, err = parseDiskutilAPFSRoles([]byte("not a plist"))
	assert.Error(t, err)
	_, err = parseDiskutilInfo([]byte("not a plist"))
	assert.Error(t, err)
}
