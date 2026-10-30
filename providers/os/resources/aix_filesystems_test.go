// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestAixFilesystem(t *testing.T) {
	rt := newAixRuntime(t, aixPlatform, map[string]string{
		"/etc/filesystems": "aix/testdata/filesystems_aix73.txt",
	}, nil)
	r, err := NewResource(rt, "aix.filesystem", map[string]*llx.RawData{"mountPoint": llx.StringData("/tmp")})
	require.NoError(t, err)
	tmp := r.(*mqlAixFilesystem)
	assert.Equal(t, "/dev/hd3", tmp.Dev.Data)
	assert.Equal(t, "jfs2", tmp.Vfs.Data)
	assert.Equal(t, "automatic", tmp.MountAtBoot.Data)
	assert.Equal(t, "/dev/hd8", tmp.Log.Data)
	// /tmp sets neither account nor nodename
	assert.True(t, tmp.Account.IsNull())
	assert.True(t, tmp.Nodename.IsNull())

	r, err = NewResource(rt, "aix.filesystem", map[string]*llx.RawData{"mountPoint": llx.StringData("/var/adm/ras/livedump")})
	require.NoError(t, err)
	livedump := r.(*mqlAixFilesystem)
	assert.False(t, livedump.Account.IsNull())
	assert.False(t, livedump.Account.Data)

	r, err = NewResource(rt, "aix.filesystem", map[string]*llx.RawData{"mountPoint": llx.StringData("/mqlfs")})
	require.NoError(t, err)
	assert.Equal(t, []any{"rw"}, r.(*mqlAixFilesystem).Options.Data)

	_, err = NewResource(rt, "aix.filesystem", map[string]*llx.RawData{"mountPoint": llx.StringData("/nope")})
	assert.Error(t, err)
}
