// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
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

// The fstab resource is selected by path, so its __id has to carry that path.
// Without an id() every fstab shares the empty cache key and the second
// fstab(...) in a query resolves to the first one's file.
func TestFstabIDIsPerFile(t *testing.T) {
	mk := func(path string) *mqlFstab {
		return &mqlFstab{Path: plugin.TValue[string]{Data: path, State: plugin.StateIsSet}}
	}

	etc, err := mk("/etc/fstab").id()
	assert.NoError(t, err)
	alt, err := mk("/tmp/fstab.alt").id()
	assert.NoError(t, err)

	assert.NotEqual(t, etc, alt,
		"two fstab files must not share an __id, or one silently serves the other")
	assert.Contains(t, etc, "/etc/fstab")

	again, err := mk("/etc/fstab").id()
	assert.NoError(t, err)
	assert.Equal(t, etc, again, "__id must be stable across calls")
}

// initFstab is what supplies the default path. os.linux.fstab has to go
// through it (NewResource), not around it (CreateResource).
func TestInitFstabDefaultsToEtcFstab(t *testing.T) {
	args, res, err := initFstab(nil, map[string]*llx.RawData{})
	assert.NoError(t, err)
	assert.Nil(t, res)
	assert.Equal(t, "/etc/fstab", args["path"].Value)
}

func newFstabTestRuntime(t *testing.T, files map[string]string) *plugin.Runtime {
	t.Helper()

	data := &mock.TomlData{Files: map[string]*mock.MockFileData{}}
	for path, content := range files {
		data.Files[path] = &mock.MockFileData{Path: path, Content: content, StatData: mock.FileInfo{Mode: 0o644}}
	}

	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "debian", Family: []string{"debian", "linux"}},
	}, mock.WithData(data))
	require.NoError(t, err)

	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

// Most container images (almalinux:10, busybox, distroless), and macOS, ship
// without /etc/fstab. That is "no static mounts", not an error.
func TestFstabEntriesMissingFileIsEmpty(t *testing.T) {
	for _, path := range []string{"/etc/fstab", "/tmp/fstab.alt"} {
		t.Run(path, func(t *testing.T) {
			f := &mqlFstab{
				MqlRuntime: newFstabTestRuntime(t, nil),
				Path:       plugin.TValue[string]{Data: path, State: plugin.StateIsSet},
			}
			entries, err := f.entries()
			require.NoError(t, err)
			assert.NotNil(t, entries, "a missing fstab must be an empty list, not null")
			assert.Empty(t, entries)
		})
	}
}

func TestFstabEntriesParsesFile(t *testing.T) {
	// /etc/fstab of a Debian 12 EC2 instance
	runtime := newFstabTestRuntime(t, map[string]string{
		"/etc/fstab": "PARTUUID=5bef6505-7977-4726-9226-72e4a542b837 / ext4 rw,discard,errors=remount-ro,x-systemd.growfs 0 1\n" +
			"PARTUUID=965e8c4a-c647-492f-b2ae-71c87aad6e91 /boot/efi vfat defaults 0 0\n",
	})
	f := &mqlFstab{
		MqlRuntime: runtime,
		Path:       plugin.TValue[string]{Data: "/etc/fstab", State: plugin.StateIsSet},
	}
	entries, err := f.entries()
	require.NoError(t, err)
	require.Len(t, entries, 2)
	first := entries[0].(*mqlFstabEntry)
	assert.Equal(t, "/", first.Mountpoint.Data)
	assert.Equal(t, "ext4", first.Fstype.Data)
}
