// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mount_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/mount"
)

func TestMountLinuxParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Family: []string{"linux"}},
	}, mock.WithPath("./testdata/debian.toml"))
	require.NoError(t, err)

	f, err := mock.RunCommand("mount")
	require.NoError(t, err)

	entries := mount.ParseLinuxMountCmd(f.Stdout)
	assert.Equal(t, 25, len(entries))

	// /dev/sda1 on / type ext4 (rw,relatime,data=ordered)
	expected := &mount.MountPoint{
		Device:     "/dev/sda1",
		MountPoint: "/",
		FSType:     "ext4",
		Options: map[string]string{
			"rw":       "",
			"relatime": "",
			"data":     "ordered",
		},
	}
	found := findMountpoint(entries, "/")
	assert.True(t, cmp.Equal(expected, found), cmp.Diff(expected, found))
}

func TestMountMacosParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Family: []string{"unix"}},
	}, mock.WithPath("./testdata/osx.toml"))
	require.NoError(t, err)

	f, err := mock.RunCommand("mount")
	require.NoError(t, err)

	entries := mount.ParseUnixMountCmd(f.Stdout)
	assert.Equal(t, 5, len(entries))

	home := findMountpoint(entries, "/System/Volumes/Data/home")
	require.NotNil(t, home)
	assert.Equal(t, "map auto_home", home.Device)
	assert.Equal(t, "autofs", home.FSType)

	expected := &mount.MountPoint{
		Device:     "/dev/disk1s5",
		MountPoint: "/",
		FSType:     "apfs",
		Options: map[string]string{
			"apfs":      "",
			"local":     "",
			"read-only": "",
			"journaled": "",
		},
	}
	found := findMountpoint(entries, "/")
	assert.True(t, cmp.Equal(expected, found), cmp.Diff(expected, found))
}

func TestMountFreeBsdParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Family: []string{"unix"}},
	}, mock.WithPath("./testdata/freebsd12.toml"))
	require.NoError(t, err)

	f, err := mock.RunCommand("mount")
	require.NoError(t, err)

	entries := mount.ParseUnixMountCmd(f.Stdout)
	assert.Equal(t, 2, len(entries))

	expected := &mount.MountPoint{
		Device:     "/dev/gpt/rootfs",
		MountPoint: "/",
		FSType:     "ufs",
		Options: map[string]string{
			"ufs":          "",
			"local":        "",
			"soft-updates": "",
		},
	}
	found := findMountpoint(entries, "/")
	assert.True(t, cmp.Equal(expected, found), cmp.Diff(expected, found))
}

func TestProcModulesParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Family: []string{"linux"}},
	}, mock.WithPath("./testdata/debian.toml"))
	require.NoError(t, err)

	f, err := mock.FileSystem().Open("/proc/mounts")
	require.NoError(t, err)
	defer f.Close()

	entries := mount.ParseLinuxProcMount(f)
	assert.Equal(t, 25, len(entries))

	// /dev/sda1 on / type ext4 (rw,relatime,data=ordered)
	expected := &mount.MountPoint{
		Device:     "/dev/sda1",
		MountPoint: "/",
		FSType:     "ext4",
		Options: map[string]string{
			"rw":       "",
			"relatime": "",
			"data":     "ordered",
		},
	}
	found := findMountpoint(entries, "/")
	assert.True(t, cmp.Equal(expected, found), cmp.Diff(expected, found))
}

func findMountpoint(mounts []mount.MountPoint, name string) *mount.MountPoint {
	for i := range mounts {
		if mounts[i].MountPoint == name {
			return &mounts[i]
		}
	}
	return nil
}

var fstabExample = `
# 
# /etc/fstab: static file system information
#
# <file system>	<dir>	<type>	<options>	<dump>	<pass>
# /dev/sdc2
UUID=6c44ec5a-4727-47d4-b485-81cff72b207e	/         	ext4      	rw,relatime,data=ordered	0 1

# /dev/sdc1
UUID=0EC7-F4C1      	/boot     	vfat      	rw,relatime,fmask=0022,dmask=0022,iocharset=iso8859-1	0 2

UUID=6060df9a-7e53-439c-9189-ba9657161fd4       /data           btrfs           rw,nofail              0 2
`

func TestFstab(t *testing.T) {
	r := strings.NewReader(fstabExample)

	entries, err := mount.ParseFstab(r)
	require.NoError(t, err)

	// /dev/sda1 on / type ext4 (rw,relatime,data=ordered)
	expected := []mount.MountPoint{
		{
			Device:     "UUID=6c44ec5a-4727-47d4-b485-81cff72b207e",
			MountPoint: "/",
			FSType:     "ext4",
			Options: map[string]string{
				"rw":       "",
				"relatime": "",
				"data":     "ordered",
			},
		},
		{
			Device:     "UUID=0EC7-F4C1",
			MountPoint: "/boot",
			FSType:     "vfat",
			Options: map[string]string{
				"rw":        "",
				"relatime":  "",
				"fmask":     "0022",
				"dmask":     "0022",
				"iocharset": "iso8859-1",
			},
		},
		{
			Device:     "UUID=6060df9a-7e53-439c-9189-ba9657161fd4",
			MountPoint: "/data",
			FSType:     "btrfs",
			Options: map[string]string{
				"rw":     "",
				"nofail": "",
			},
		},
	}

	assert.Equal(t, expected, entries)
}

// Captured from `mount -v` on Oracle Solaris 11.4.86 with a nosuid,noexec
// tmpfs on /mnt/tmp and a read-only lofs on /mnt/ro.
func TestMountSolarisParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "solaris", Family: []string{"unix"}},
	}, mock.WithPath("./testdata/solaris114.toml"))
	require.NoError(t, err)

	f, err := mock.RunCommand("mount -v")
	require.NoError(t, err)

	entries := mount.ParseSolarisMountCmd(f.Stdout)
	require.Equal(t, 30, len(entries))

	root := findMountpoint(entries, "/")
	require.NotNil(t, root)
	assert.Equal(t, "rpool/ROOT/11.4.86.201.2", root.Device)
	assert.Equal(t, "zfs", root.FSType)
	assert.Equal(t, map[string]string{
		"rw": "", "setuid": "", "devices": "", "rstchown": "", "dev": "3610002",
	}, root.Options)

	tmp := findMountpoint(entries, "/mnt/tmp")
	require.NotNil(t, tmp)
	assert.Equal(t, "swap", tmp.Device)
	assert.Equal(t, "tmpfs", tmp.FSType)
	assert.Contains(t, tmp.Options, "nosetuid")
	assert.Contains(t, tmp.Options, "noexec")
	assert.Contains(t, tmp.Options, "nodevices")
	assert.Equal(t, "10m", tmp.Options["size"])

	ro := findMountpoint(entries, "/mnt/ro")
	require.NotNil(t, ro)
	assert.Equal(t, "lofs", ro.FSType)
	assert.Contains(t, ro.Options, "ro")
	assert.NotContains(t, ro.Options, "rw")
	assert.NotContains(t, ro.Options, "read-only")

	// the epoch-dated root and the dated rest both parse
	assert.NotNil(t, findMountpoint(entries, "/var/share"))
}
