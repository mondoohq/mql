// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/mount"
	"go.mondoo.com/mql/utils/syncx"
)

func dfMockRuntime(t *testing.T, df *mock.Command) *plugin.Runtime {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "solaris", Family: []string{"unix", "os"}},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{"df -P -k": df},
		Files:    map[string]*mock.MockFileData{},
	}))
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

// An unprivileged df on Solaris 11.4 cannot stat /var/share/sstore/repo,
// exits 1, and still prints every other mount (abridged from a real run). A
// single unreadable mount point used to cost every mount its size.
func TestDfPartialOutput(t *testing.T) {
	runtime := dfMockRuntime(t, &mock.Command{
		Stdout: "Filesystem           1024-blocks        Used   Available Capacity  Mounted on\n" +
			"rpool/ROOT/11.4.86.201.2    51331392     1291512    39406676     4%    /\n" +
			"swap                   15333840         188    15333652     1%    /tmp\n",
		Stderr:     "df: cannot statvfs /var/share/sstore/repo: Permission denied\n",
		ExitStatus: 1,
	})

	obj, err := CreateResource(runtime, "mount", nil)
	require.NoError(t, err)
	entries, err := obj.(*mqlMount).fetchDfEntries()
	require.NoError(t, err)

	require.Contains(t, entries, "/tmp")
	assert.Equal(t, int64(15333840*1024), entries["/tmp"].Size)
	assert.Contains(t, entries, "/")
}

// A df that prints nothing at all could not answer: no capacity, no error.
func TestDfFailedOutright(t *testing.T) {
	runtime := dfMockRuntime(t, &mock.Command{
		Stderr:     "sh: df: not found\n",
		ExitStatus: 127,
	})

	obj, err := CreateResource(runtime, "mount", nil)
	require.NoError(t, err)
	entries, err := obj.(*mqlMount).fetchDfEntries()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// df -P -k on RHEL 9 with /mnt/lvlin bind-mounted at /mnt/fixbind: GNU df
// lists the logical volume once, under /mnt/lvlin.
const rhel9DfWithBindMount = `Filesystem                   1024-blocks    Used Available Capacity Mounted on
tmpfs                             877388       0    877388       0% /dev/shm
tmpfs                             350956   20420    330536       6% /run
/dev/nvme1n1p2                    204580    7600    196980       4% /boot/efi
/dev/mapper/vg--data-lv--lin      498900      24    462180       1% /mnt/lvlin
tank                             1770112     128   1769984       1% /tank
127.0.0.1:/srv/nfs/ro           30136320 6168064  23968256      21% /mnt/nfs4
tmpfs                             175476       0    175476       0% /run/user/1000
`

func TestDfEntryForSecondMountOfADevice(t *testing.T) {
	entries := mount.ParseDf(strings.NewReader(rhel9DfWithBindMount))

	bind := dfEntryFor(entries, "/mnt/fixbind", "/dev/mapper/vg--data-lv--lin")
	require.NotNil(t, bind)
	assert.Equal(t, int64(498900*1024), bind.Size)
	assert.Equal(t, int64(24*1024), bind.Used)

	// the EFI system partition, also mounted at /efi by systemd's automount
	require.NotNil(t, dfEntryFor(entries, "/efi", "/dev/nvme1n1p2"))

	// listed mounts are read as before
	assert.Equal(t, int64(350956*1024), dfEntryFor(entries, "/run", "tmpfs").Size)

	// a tmpfs, an NFS export or a ZFS dataset names no block device: another
	// mount with the same source is a different filesystem
	assert.Nil(t, dfEntryFor(entries, "/mnt/other-tmpfs", "tmpfs"))
	assert.Nil(t, dfEntryFor(entries, "/mnt/nfs-again", "127.0.0.1:/srv/nfs/ro"))
	assert.Nil(t, dfEntryFor(entries, "/mnt/tank-again", "tank"))
	// a block device df does not list at all stays unknown
	assert.Nil(t, dfEntryFor(entries, "/mnt/x", "/dev/sdz1"))
}
