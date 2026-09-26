// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

// A second account or group with an ID or name that is already taken (a UID 0
// alias such as "toor") must not replace the first entry. getpwuid, getgrgid,
// getpwnam and getgrnam return the first match, and checks that compare a file
// owner with "root" rely on the same answer.
func TestIDAliasesResolveToFirstEntry(t *testing.T) {
	fixturePath, err := filepath.Abs("testdata/id_aliases.toml")
	require.NoError(t, err)

	asset := &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "rockylinux",
			Family: []string{"redhat", "linux", "unix"},
		},
	}
	conn, err := mock.New(0, asset, mock.WithPath(fixturePath))
	require.NoError(t, err)

	runtime := &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}

	raw, err := CreateResource(runtime, "users", nil)
	require.NoError(t, err)
	users := raw.(*mqlUsers)

	root, err := users.findID(0)
	require.NoError(t, err)
	assert.Equal(t, "root", root.Name.Data)
	require.NoError(t, users.GetList().Error)
	assert.Equal(t, int64(1), users.usersByName["daemon"].Uid.Data)

	raw, err = CreateResource(runtime, "groups", nil)
	require.NoError(t, err)
	groups := raw.(*mqlGroups)

	rootGroup, err := groups.findID(0)
	require.NoError(t, err)
	assert.Equal(t, "root", rootGroup.Name.Data)
	assert.Equal(t, int64(1), groups.groupsByName["daemon"].Gid.Data)
}
