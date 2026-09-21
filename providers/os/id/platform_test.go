// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package id_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/fs"
	"go.mondoo.com/mql/providers/os/id"
	"go.mondoo.com/mql/providers/os/id/ids"
)

const mountPathIDPrefix = "//platformid.api.mondoo.app/runtime/filesystem/hash/"

func fsConn(t *testing.T, path string) *fs.FileSystemConnection {
	t.Helper()
	conn, err := fs.NewConnection(0, &inventory.Config{Path: path}, &inventory.Asset{})
	require.NoError(t, err)
	return conn
}

// A container root filesystem carries an empty /etc/hostname, because the
// runtime writes the hostname at container start and never into the image
// layers. The asset still has to end up with an identifier.
func TestIdentifyPlatform_ContainerRootfsWithoutHostname(t *testing.T) {
	conn := fsConn(t, "./testdata/container-rootfs")

	fingerprint, pf, err := id.IdentifyPlatform(conn, &plugin.ConnectReq{}, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, fingerprint)

	assert.Equal(t, "ubuntu", pf.Name)
	require.Len(t, fingerprint.PlatformIDs, 1)
	assert.True(t, strings.HasPrefix(fingerprint.PlatformIDs[0], mountPathIDPrefix),
		"expected a mount path identifier, got %q", fingerprint.PlatformIDs[0])
	assert.Contains(t, fingerprint.ActiveIdDetectors, ids.IdDetector_MountPath)

	abs, err := filepath.Abs("./testdata/container-rootfs")
	require.NoError(t, err)
	assert.Equal(t, abs, fingerprint.Name)
}

// The mount path identifier is derived from the path alone, so the same tree
// resolves to the same asset on every scan and two trees never share an id.
func TestIdentifyPlatform_MountPathIDIsStableAndDistinct(t *testing.T) {
	first, _, err := id.IdentifyPlatform(fsConn(t, "./testdata/container-rootfs"), &plugin.ConnectReq{}, nil, nil)
	require.NoError(t, err)
	again, _, err := id.IdentifyPlatform(fsConn(t, "./testdata/container-rootfs"), &plugin.ConnectReq{}, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, first.PlatformIDs, again.PlatformIDs)

	// A relative and an absolute spelling of the same directory are the same asset.
	abs, err := filepath.Abs("./testdata/container-rootfs")
	require.NoError(t, err)
	absolute, _, err := id.IdentifyPlatform(fsConn(t, abs), &plugin.ConnectReq{}, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, first.PlatformIDs, absolute.PlatformIDs)
}

// A machine id is a real identity and outranks the synthetic one, so a mounted
// host root that never wrote /etc/hostname keeps a stable id across scans even
// when the mount point moves.
func TestIdentifyPlatform_PrefersMachineIDOverMountPath(t *testing.T) {
	conn := fsConn(t, "./testdata/machineid-rootfs")

	fingerprint, _, err := id.IdentifyPlatform(conn, &plugin.ConnectReq{}, nil, nil)
	require.NoError(t, err)
	require.Len(t, fingerprint.PlatformIDs, 1)
	assert.Equal(t, "//platformid.api.mondoo.app/machineid/ee1a5d4b8f0d4b1ea2d1b0b7c9e5f2a3", fingerprint.PlatformIDs[0])
	assert.NotContains(t, fingerprint.ActiveIdDetectors, ids.IdDetector_MountPath)
}

// The fallbacks must not fire when the hostname resolves: adding a second id to
// an asset that already has one changes how it is matched upstream.
func TestIdentifyPlatform_HostnameWins(t *testing.T) {
	conn := fsConn(t, "./testdata/host-rootfs")

	fingerprint, _, err := id.IdentifyPlatform(conn, &plugin.ConnectReq{}, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"//platformid.api.mondoo.app/hostname/web-01"}, fingerprint.PlatformIDs)
	assert.Equal(t, "web-01", fingerprint.Name)
	assert.Equal(t, []string{ids.IdDetector_Hostname}, fingerprint.ActiveIdDetectors)
}
