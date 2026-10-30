// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func volumeByDevice(t *testing.T, vols []Volume, deviceID string) Volume {
	t.Helper()
	for _, v := range vols {
		if v.DeviceID == deviceID {
			return v
		}
	}
	require.Failf(t, "volume not found", "no volume %s", deviceID)
	return Volume{}
}

// The fixture is the VolumesScript output of a Windows Server 2022 host with a
// system volume, a lettered data volume, and a volume mounted only into the
// folder C:\mnt\data.
func TestParseVolumesServer2022(t *testing.T) {
	data, err := os.ReadFile("./testdata/volumes-ws2022.json")
	require.NoError(t, err)

	vols, err := ParseVolumes(data)
	require.NoError(t, err)
	require.Len(t, vols, 3)

	sys := volumeByDevice(t, vols, `\\?\Volume{01cef182-0000-0000-0000-100000000000}\`)
	assert.Equal(t, []string{`C:\`}, sys.AccessPaths)
	assert.Equal(t, "NTFS", sys.FileSystem)
	assert.Equal(t, "Fixed", sys.DriveType)
	assert.Equal(t, "", sys.Label)
	require.NotNil(t, sys.Capacity)
	require.NotNil(t, sys.FreeSpace)
	assert.Equal(t, int64(64422408192), *sys.Capacity)
	assert.Equal(t, int64(42523316224), *sys.FreeSpace)
	assert.True(t, sys.BootVolume)
	assert.True(t, sys.SystemVolume)
	assert.True(t, sys.PageFile)
	assert.False(t, sys.Compressed)

	data1 := volumeByDevice(t, vols, `\\?\Volume{66d55a38-a842-4b96-9a57-04aca40889ea}\`)
	assert.Equal(t, []string{`E:\`}, data1.AccessPaths)
	assert.Equal(t, "MQLDATA", data1.Label)
	assert.False(t, data1.BootVolume)
	assert.False(t, data1.PageFile)

	// Win32_Volume.Name says C:\mnt\data\ and Win32_MountPoint says
	// C:\mnt\data. They are one access path, not two.
	folder := volumeByDevice(t, vols, `\\?\Volume{d24a16dc-fc72-48eb-9637-69658f6281c7}\`)
	assert.Equal(t, []string{`C:\mnt\data`}, folder.AccessPaths)
	assert.Equal(t, "MQLFOLDER", folder.Label)
	require.NotNil(t, folder.Capacity)
	assert.Equal(t, int64(6424621056), *folder.Capacity)
}

func TestParseVolumesAccessPaths(t *testing.T) {
	data := []byte(`{
		"volumes": [
			{"DeviceID":"\\\\?\\Volume{aaaa}\\","Name":"E:\\","DriveLetter":"E:","DriveType":3,"FileSystem":"ReFS","Capacity":100,"FreeSpace":40},
			{"DeviceID":"\\\\?\\Volume{bbbb}\\","Name":"\\\\?\\Volume{bbbb}\\","DriveLetter":null,"DriveType":3,"FileSystem":"FAT32","Capacity":104857600,"FreeSpace":73400320},
			{"DeviceID":"\\\\?\\Volume{cccc}\\","Name":"D:\\","DriveLetter":"D:","DriveType":5,"FileSystem":null,"Capacity":null,"FreeSpace":null}
		],
		"mountPoints": [
			{"Volume":"\\\\?\\Volume{AAAA}\\","Directory":"E:\\"},
			{"Volume":"\\\\?\\Volume{aaaa}\\","Directory":"C:\\mnt\\e"},
			{"Volume":"\\\\?\\Volume{cccc}\\","Directory":"D:\\"}
		]
	}`)
	vols, err := ParseVolumes(data)
	require.NoError(t, err)
	require.Len(t, vols, 3)

	// Both access paths of a volume, matched by DeviceID without regard to
	// case, and E:\ reported once although three sources name it.
	multi := volumeByDevice(t, vols, `\\?\Volume{aaaa}\`)
	assert.Equal(t, []string{`C:\mnt\e`, `E:\`}, multi.AccessPaths)
	assert.Equal(t, "ReFS", multi.FileSystem)

	// No drive letter and no folder: reported at its volume GUID path.
	hidden := volumeByDevice(t, vols, `\\?\Volume{bbbb}\`)
	assert.Equal(t, []string{`\\?\Volume{bbbb}\`}, hidden.AccessPaths)
	assert.Equal(t, "FAT32", hidden.FileSystem)

	// An optical drive with no disc has a letter and nothing else. Its
	// capacity was not measured, so it stays nil rather than reading 0.
	empty := volumeByDevice(t, vols, `\\?\Volume{cccc}\`)
	assert.Equal(t, []string{`D:\`}, empty.AccessPaths)
	assert.Equal(t, "CDRom", empty.DriveType)
	assert.Equal(t, "", empty.FileSystem)
	assert.Nil(t, empty.Capacity)
	assert.Nil(t, empty.FreeSpace)
}

// A single volume can be flattened out of its array.
func TestParseVolumesSingleElement(t *testing.T) {
	data := []byte(`{"volumes":{"DeviceID":"\\\\?\\Volume{aaaa}\\","Name":"C:\\","DriveType":3,"FileSystem":"NTFS","Capacity":10,"FreeSpace":5},"mountPoints":{"Volume":"\\\\?\\Volume{aaaa}\\","Directory":"C:\\"}}`)
	vols, err := ParseVolumes(data)
	require.NoError(t, err)
	require.Len(t, vols, 1)
	assert.Equal(t, []string{`C:\`}, vols[0].AccessPaths)
}

func TestVolumesResult(t *testing.T) {
	t.Run("failed script reports its stderr", func(t *testing.T) {
		_, err := VolumesResult(nil, 1, []byte("could not read Win32_Volume: Access denied"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Access denied")
	})
	t.Run("no output is not an empty volume table", func(t *testing.T) {
		_, err := VolumesResult([]byte("  \r\n"), 0, nil)
		require.Error(t, err)
	})
	t.Run("no volumes is not an answer", func(t *testing.T) {
		_, err := VolumesResult([]byte(`{"volumes":[],"mountPoints":[]}`), 0, nil)
		require.Error(t, err)
	})
	t.Run("unparseable output is malformed data", func(t *testing.T) {
		_, err := VolumesResult([]byte(`{"volumes":[{`), 0, nil)
		require.Error(t, err)
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_MALFORMED_DATA, llx.KindOf(err))
	})
}

func TestVolumePath(t *testing.T) {
	cases := map[string]string{
		`C:`:                  `C:\`,
		`C:\`:                 `C:\`,
		`c:/`:                 `c:\`,
		`C:\mnt\data\`:        `C:\mnt\data`,
		`C:\mnt\data`:         `C:\mnt\data`,
		`\\?\Volume{abcd}\`:   `\\?\Volume{abcd}\`,
		`\\?\Volume{abcd}`:    `\\?\Volume{abcd}\`,
		`C:/mnt/data/`:        `C:\mnt\data`,
		`C:\Program Files\x\`: `C:\Program Files\x`,
	}
	for in, want := range cases {
		assert.Equal(t, want, VolumePath(in), "VolumePath(%q)", in)
	}
}

func TestVolumePathKey(t *testing.T) {
	for _, p := range []string{`C:`, `C:\`, `c:\`, `c:/`, `C:\\`} {
		assert.Equal(t, "c:", VolumePathKey(p), "VolumePathKey(%q)", p)
	}
	assert.Equal(t, VolumePathKey(`C:\mnt\data`), VolumePathKey(`c:\MNT\Data\`))
	assert.NotEqual(t, VolumePathKey(`C:\`), VolumePathKey(`C:\mnt\data`))
	assert.NotEqual(t, VolumePathKey(`C:\`), VolumePathKey(`D:\`))
}

func TestVolumeDriveTypeName(t *testing.T) {
	assert.Equal(t, "Fixed", VolumeDriveTypeName(3))
	assert.Equal(t, "Removable", VolumeDriveTypeName(2))
	assert.Equal(t, "9", VolumeDriveTypeName(9))
}
