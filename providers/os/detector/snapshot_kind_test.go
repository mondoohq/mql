// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	archivetar "archive/tar"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/docker"
	"go.mondoo.com/mql/providers/os/connection/tar"
)

// debian:12's os-release, as exported from a stopped container
const debian12OsRelease = `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
`

// A stopped container is scanned from an export of its filesystem. It was
// reported as kind baremetal with no runtime ("Bare metal system"), because
// only the tar and running-container connections set the kind.
func TestStoppedContainerIsAContainer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "export.tar")
	f, err := os.Create(path)
	require.NoError(t, err)
	tw := archivetar.NewWriter(f)
	require.NoError(t, tw.WriteHeader(&archivetar.Header{Name: "etc/os-release", Typeflag: archivetar.TypeReg, Mode: 0o644, Size: int64(len(debian12OsRelease))}))
	_, err = tw.Write([]byte(debian12OsRelease))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, f.Close())

	tc, err := tar.NewConnection(0, &inventory.Config{Type: "docker-snapshot", Options: map[string]string{tar.OPTION_FILE: path}}, &inventory.Asset{})
	require.NoError(t, err)

	pf, ok := DetectOS(&docker.SnapshotConnection{Connection: tc})
	require.True(t, ok)
	assert.Equal(t, "debian", pf.Name)
	assert.Equal(t, "container", pf.Kind)
	assert.Equal(t, "docker-container", pf.Runtime)
}
