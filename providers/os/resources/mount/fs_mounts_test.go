// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mount

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An image, a tar or a filesystem scan has no /proc/mounts and falls back to
// /etc/fstab. fstab says what would be mounted at boot, not what is mounted,
// so its entries must not read as mounted: Alpine's image reported its
// noauto /dev/cdrom as mounted.
func TestFstabFallbackIsNotMounted(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/etc/fstab",
		[]byte("/dev/cdrom\t/media/cdrom\tiso9660\tnoauto,ro 0 0\n/dev/usbdisk\t/media/usb\tvfat\tnoauto,ro 0 0\n"), 0o644))

	mounts, err := mountsFromFSLinux(fs)
	require.NoError(t, err)
	require.Len(t, mounts, 2)
	for _, m := range mounts {
		assert.True(t, m.Unmounted, m.MountPoint)
	}
}

func TestProcMountsAreMounted(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/proc/mounts",
		[]byte("overlay / overlay rw,relatime 0 0\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/etc/fstab",
		[]byte("/dev/cdrom\t/media/cdrom\tiso9660\tnoauto,ro 0 0\n"), 0o644))

	mounts, err := mountsFromFSLinux(fs)
	require.NoError(t, err)
	require.Len(t, mounts, 1)
	assert.Equal(t, "/", mounts[0].MountPoint)
	assert.False(t, mounts[0].Unmounted)
}
