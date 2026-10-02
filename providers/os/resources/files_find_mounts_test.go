// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

func newFilesFind(t *testing.T, platform *inventory.Platform, mounts string, gnuFind bool) *mqlFilesFind {
	t.Helper()
	cmds := map[string]*mock.Command{}
	if gnuFind {
		cmds["find --version"] = &mock.Command{Stdout: "find (GNU findutils) 4.10.0\n"}
	}
	if mounts != "" {
		cmds[procMountsCmd] = &mock.Command{Stdout: mounts}
	}
	conn, err := mock.New(0, &inventory.Asset{Platform: platform}, mock.WithData(&mock.TomlData{Commands: cmds}))
	require.NoError(t, err)
	l := &mqlFilesFind{MqlRuntime: &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}}
	l.From = plugin.TValue[string]{Data: "/srv/g05files", State: plugin.StateIsSet}
	l.Xdev = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
	l.Type = plugin.TValue[string]{Data: "file", State: plugin.StateIsSet}
	l.Permissions = plugin.TValue[int64]{Data: 0o002, State: plugin.StateIsSet}
	return l
}

// A SLES 16 search for world-writable files below /srv/g05files, which holds
// a Btrfs subvolume that is not mounted. -xdev would skip that subvolume.
func TestFilesFindPrunesMountsOnBtrfs(t *testing.T) {
	raw, err := os.ReadFile("filesfind/testdata/sles16-proc-mounts.txt")
	require.NoError(t, err)
	mounts := string(raw)
	sles := &inventory.Platform{Name: "sles", Family: []string{"suse", "linux", "unix", "os"}}

	l := newFilesFind(t, sles, mounts, true)
	assert.Equal(t, `find -L "/srv/g05files" \( -xtype l -prune -o -true \) -type f -perm -2 -print`, l.unixFindCommand(nil))

	// Crossing filesystems was asked for: nothing to prune, no -xdev.
	l = newFilesFind(t, sles, mounts, true)
	l.Xdev.Data = true
	assert.Equal(t, `find -L "/srv/g05files" \( -xtype l -prune -o -true \) -type f -perm -2 -print`, l.unixFindCommand(nil))

	// Without GNU find, or without a readable mount table, the search keeps -xdev.
	l = newFilesFind(t, sles, mounts, false)
	assert.Equal(t, `find -L "/srv/g05files" -xdev -type f -perm -2`, l.unixFindCommand(nil))
	l = newFilesFind(t, sles, "", true)
	assert.Equal(t, `find -L "/srv/g05files" -xdev \( -xtype l -prune -o -true \) -type f -perm -2 -print`, l.unixFindCommand(nil))

	// A link search follows symlinked directories, which a pruned path does
	// not cover, so it keeps -xdev.
	l = newFilesFind(t, sles, mounts, true)
	l.Type.Data = "link"
	assert.Equal(t, `find -L "/srv/g05files" -xdev -xtype l -perm -2`, l.unixFindCommand(nil))

	// The mount table is a Linux one, read only on Linux.
	macos := &inventory.Platform{Name: "macos", Family: []string{"darwin", "bsd", "unix", "os"}}
	l = newFilesFind(t, macos, mounts, true)
	assert.Equal(t, `find -L "/srv/g05files" -xdev \( -xtype l -prune -o -true \) -type f -perm -2 -print`, l.unixFindCommand(nil))
}

// On XFS, ext4 and every other filesystem without subvolumes the command is
// unchanged.
func TestFilesFindKeepsXdevWithoutSubvolumes(t *testing.T) {
	raw, err := os.ReadFile("filesfind/testdata/sles15-proc-mounts.txt")
	require.NoError(t, err)
	mounts := string(raw)
	l := newFilesFind(t, &inventory.Platform{Name: "sles", Family: []string{"suse", "linux", "unix", "os"}}, mounts, true)
	assert.Equal(t, `find -L "/srv/g05files" -xdev \( -xtype l -prune -o -true \) -type f -perm -2 -print`, l.unixFindCommand(nil))
}
