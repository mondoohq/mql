// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/fs"
)

func TestListWithoutRunningSystem(t *testing.T) {
	// a file system connection reads an image or a snapshot: nothing runs
	conn, err := fs.NewFileSystemConnectionWithFs(0, &inventory.Config{}, &inventory.Asset{
		Platform: &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}},
	}, "", nil, afero.NewMemMapFs())
	require.NoError(t, err)
	bins, err := List(conn)
	require.NoError(t, err)
	assert.Empty(t, bins)
	assert.NotNil(t, bins)
}
