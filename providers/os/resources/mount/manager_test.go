// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mount_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/mount"
)

func TestManagerDebian(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Family: []string{"linux"}},
	}, mock.WithPath("./testdata/debian.toml"))
	require.NoError(t, err)

	mm, err := mount.ResolveManager(mock)
	require.NoError(t, err)
	mounts, err := mm.List()
	require.NoError(t, err)

	assert.Equal(t, 25, len(mounts))
}

func TestManagerMacos(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Family: []string{"unix"}},
	}, mock.WithPath("./testdata/osx.toml"))
	require.NoError(t, err)

	mm, err := mount.ResolveManager(mock)
	require.NoError(t, err)
	mounts, err := mm.List()
	require.NoError(t, err)

	// includes "map auto_home", whose device name holds a space
	assert.Equal(t, 5, len(mounts))
}

func TestManagerFreebsd(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Family: []string{"unix"}},
	}, mock.WithPath("./testdata/freebsd12.toml"))
	require.NoError(t, err)

	mm, err := mount.ResolveManager(mock)
	require.NoError(t, err)
	mounts, err := mm.List()
	require.NoError(t, err)

	assert.Equal(t, 2, len(mounts))
}

// A host with a command capability but no `mount` binary is not a host with
// nothing mounted. Before the fallback, the missing command's empty stdout
// parsed to an empty list and the resource reported that as fact.
func TestManagerFallsBackToProcMountsWhenCommandIsMissing(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Family: []string{"linux"}},
	}, mock.WithPath("./testdata/no-mount-command.toml"))
	require.NoError(t, err)

	mm, err := mount.ResolveManager(mock)
	require.NoError(t, err)
	mounts, err := mm.List()
	require.NoError(t, err)

	require.Len(t, mounts, 7, "the mounts must come from /proc/mounts")

	byPath := map[string]mount.MountPoint{}
	for _, m := range mounts {
		byPath[m.MountPoint] = m
	}
	root, ok := byPath["/"]
	require.True(t, ok, "the root mount must be reported")
	assert.Equal(t, "/dev/nvme0n1p1", root.Device)
	assert.Equal(t, "ext4", root.FSType)
	assert.Contains(t, root.Options, "rw")
}

// Same when the binary exists but refuses to answer.
func TestManagerFallsBackToProcMountsWhenCommandFails(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Family: []string{"linux"}},
	}, mock.WithPath("./testdata/failing-mount-command.toml"))
	require.NoError(t, err)

	mm, err := mount.ResolveManager(mock)
	require.NoError(t, err)
	mounts, err := mm.List()
	require.NoError(t, err)

	require.Len(t, mounts, 3)
	assert.Equal(t, "/", mounts[1].MountPoint)
	assert.Equal(t, "ext4", mounts[1].FSType)
}

// The command stays the preferred source: a host where it answers must not
// start reading /proc/mounts instead.
func TestManagerPrefersTheMountCommand(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Family: []string{"linux"}},
	}, mock.WithPath("./testdata/debian.toml"))
	require.NoError(t, err)

	mm, err := mount.ResolveManager(mock)
	require.NoError(t, err)
	mounts, err := mm.List()
	require.NoError(t, err)

	// debian.toml carries no /proc/mounts at all, so 25 entries can only have
	// come from the command.
	assert.Equal(t, 25, len(mounts))
}

// Solaris 11.4 ships /etc/os-release and is detected into the linux family.
// The linux manager's `mount` parser matched none of its lines and the
// /proc/mounts fallback does not exist there, so the list failed outright.
func TestManagerSolaris(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "solaris", Family: []string{"linux", "unix", "os"}},
	}, mock.WithPath("./testdata/solaris114.toml"))
	require.NoError(t, err)

	mm, err := mount.ResolveManager(mock)
	require.NoError(t, err)
	mounts, err := mm.List()
	require.NoError(t, err)

	assert.Equal(t, 30, len(mounts))
}
