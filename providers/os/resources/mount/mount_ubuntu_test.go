// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mount_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/mount"
)

func ubuntu2404Mounts(t *testing.T) (fromCmd []mount.MountPoint, fromProc []mount.MountPoint) {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Family: []string{"linux"}},
	}, mock.WithPath("./testdata/ubuntu2404.toml"))
	require.NoError(t, err)

	cmd, err := conn.RunCommand("mount")
	require.NoError(t, err)
	fromCmd = mount.ParseLinuxMountCmd(cmd.Stdout)

	f, err := conn.FileSystem().Open("/proc/mounts")
	require.NoError(t, err)
	defer f.Close()
	fromProc = mount.ParseLinuxProcMount(f)
	return fromCmd, fromProc
}

func TestMountPathWithSpace(t *testing.T) {
	fromCmd, fromProc := ubuntu2404Mounts(t)
	// Both list every mount, including the one whose path holds a space.
	assert.Len(t, fromCmd, 44)
	assert.Len(t, fromProc, 44)

	for _, entries := range [][]mount.MountPoint{fromCmd, fromProc} {
		sp := findMountpoint(entries, "/mnt/sp ace")
		require.NotNil(t, sp)
		assert.Equal(t, "g05sp", sp.Device)
		assert.Equal(t, "tmpfs", sp.FSType)
		assert.Equal(t, "8192k", sp.Options["size"])
	}

	root := findMountpoint(fromCmd, "/")
	require.NotNil(t, root)
	assert.Equal(t, "/dev/nvme0n1p1", root.Device)
	assert.Equal(t, "ext4", root.FSType)
}

func TestMarkOvermounted(t *testing.T) {
	fromCmd, fromProc := ubuntu2404Mounts(t)
	for _, entries := range [][]mount.MountPoint{fromCmd, fromProc} {
		mount.MarkOvermounted(entries)

		var over, binfmt []mount.MountPoint
		hidden := 0
		for _, e := range entries {
			switch e.MountPoint {
			case "/mnt/over":
				over = append(over, e)
			case "/proc/sys/fs/binfmt_misc":
				binfmt = append(binfmt, e)
			}
			if e.Overmounted {
				hidden++
			}
		}
		assert.Equal(t, 2, hidden)

		require.Len(t, over, 2)
		assert.Equal(t, "g05over1", over[0].Device)
		assert.True(t, over[0].Overmounted)
		assert.Equal(t, "g05over2", over[1].Device)
		assert.False(t, over[1].Overmounted)

		// systemd's automount point, replaced by binfmt_misc on first access
		require.Len(t, binfmt, 2)
		assert.Equal(t, "autofs", binfmt[0].FSType)
		assert.True(t, binfmt[0].Overmounted)
		assert.Equal(t, "binfmt_misc", binfmt[1].FSType)
		assert.False(t, binfmt[1].Overmounted)
	}
}

func TestProcMountsUnescape(t *testing.T) {
	entries := mount.ParseLinuxProcMount(strings.NewReader(
		"my\\040dev /mnt/a\\011b\\134c tmpfs rw 0 0\n" +
			"dev /mnt/\\400x tmpfs rw 0 0\n"))
	require.Len(t, entries, 2)
	assert.Equal(t, "my dev", entries[0].Device)
	assert.Equal(t, "/mnt/a\tb\\c", entries[0].MountPoint)
	// Not a valid escape: kept as written.
	assert.Equal(t, "/mnt/\\400x", entries[1].MountPoint)
}
