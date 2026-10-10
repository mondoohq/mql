// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestAixInittab(t *testing.T) {
	rt := newAixRuntime(t, aixPlatform, map[string]string{
		"/etc/inittab": "aix/testdata/inittab_aix73.txt",
	}, nil)
	r, err := CreateResource(rt, "aix.inittab", map[string]*llx.RawData{})
	require.NoError(t, err)
	list := r.(*mqlAixInittab).GetList()
	require.NoError(t, list.Error)

	byID := map[string]*mqlAixInittabEntry{}
	for _, x := range list.Data {
		e := x.(*mqlAixInittabEntry)
		byID[e.Id.Data] = e
	}
	assert.Equal(t, "respawn", byID["cron"].Action.Data)
	assert.True(t, byID["cron"].Active.Data)
	assert.False(t, byID["shdaemon"].Active.Data)
	assert.Equal(t, "/usr/sbin/shdaemon >/dev/console 2>&1", byID["shdaemon"].Command.Data)
}

func TestAixInittabMissing(t *testing.T) {
	rt := newAixRuntime(t, aixPlatform, nil, nil)
	r, err := CreateResource(rt, "aix.inittab", map[string]*llx.RawData{})
	require.NoError(t, err)
	list := r.(*mqlAixInittab).GetList()
	require.Error(t, list.Error)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_FOUND, llx.KindOf(list.Error))
}
