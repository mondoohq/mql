// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// This lives in `package packages` (not `packages_test`) so it can build a
// PacmanPkgManager with unexported fields, mirroring the dpkg and rpm Files
// tests.
func TestPacmanFiles(t *testing.T) {
	pf := &inventory.Platform{
		Name:   "arch",
		Arch:   "x86_64",
		Family: []string{"arch", "linux", "unix", "os"},
	}

	m, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/packages_pacman.toml"))
	require.NoError(t, err)

	mgr := &PacmanPkgManager{conn: m, platform: pf}

	// regular package -> manifest path
	files, err := mgr.Files("glibc", "2.39-1", "x86_64")
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.Equal(t, "/var/lib/pacman/local/glibc-2.39-1/files", files[0].Path)

	// epoch package -> directory suffix keeps the epoch colon
	files, err = mgr.Files("alsa-plugins", "1:1.2.12-5", "x86_64")
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.Equal(t, "/var/lib/pacman/local/alsa-plugins-1:1.2.12-5/files", files[0].Path)

	// package with no manifest on disk -> no records, no error
	files, err = mgr.Files("does-not-exist", "1.0-1", "x86_64")
	require.NoError(t, err)
	assert.Empty(t, files)

	// missing name/version -> no records, no error
	files, err = mgr.Files("", "", "")
	require.NoError(t, err)
	assert.Empty(t, files)
}
