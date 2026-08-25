// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func fstabEntry(device, mountpoint string) *mqlFstabEntry {
	return &mqlFstabEntry{
		Device:     plugin.TValue[string]{Data: device, State: plugin.StateIsSet},
		Mountpoint: plugin.TValue[string]{Data: mountpoint, State: plugin.StateIsSet},
	}
}

// Two rows sharing a device is ordinary in /etc/fstab. When their __id
// collides the runtime serves the first for both, and the later rows drop out
// of fstab.entries without any error.
func TestFstabEntryIDIsUniquePerMountPoint(t *testing.T) {
	tests := []struct {
		name string
		a    *mqlFstabEntry
		b    *mqlFstabEntry
	}{
		{
			// The reported case, and the stock layout on many distros.
			name: "two tmpfs mounts",
			a:    fstabEntry("tmpfs", "/tmp"),
			b:    fstabEntry("tmpfs", "/dev/shm"),
		},
		{
			name: "two swap devices both mounting at none",
			a:    fstabEntry("/dev/sda2", "none"),
			b:    fstabEntry("/dev/sda3", "none"),
		},
		{
			name: "two none-device pseudo filesystems",
			a:    fstabEntry("none", "/proc/sys/fs/binfmt_misc"),
			b:    fstabEntry("none", "/sys/kernel/debug"),
		},
		{
			name: "same mount point, different device",
			a:    fstabEntry("/dev/sdb1", "/data"),
			b:    fstabEntry("/dev/sdc1", "/data"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ida, err := tc.a.id()
			assert.NoError(t, err)
			idb, err := tc.b.id()
			assert.NoError(t, err)
			assert.NotEqual(t, ida, idb,
				"distinct fstab rows must not share an __id, or the later row is dropped")
		})
	}
}

func TestFstabEntryIDIsStable(t *testing.T) {
	e := fstabEntry("tmpfs", "/dev/shm")
	first, err := e.id()
	assert.NoError(t, err)
	second, err := e.id()
	assert.NoError(t, err)
	assert.Equal(t, first, second, "__id must be stable across calls")
	assert.Contains(t, first, "tmpfs")
	assert.Contains(t, first, "/dev/shm")
}
