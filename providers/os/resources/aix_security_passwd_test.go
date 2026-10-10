// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestAixSecurityPasswd(t *testing.T) {
	rt := newAixRuntime(t, aixPlatform, map[string]string{
		"/etc/security/passwd": "aix/testdata/passwd_aix73.txt",
	}, nil)
	r, err := CreateResource(rt, "aix.security.passwd", map[string]*llx.RawData{})
	require.NoError(t, err)
	list := r.(*mqlAixSecurityPasswd).GetList()
	require.NoError(t, list.Error)
	require.Len(t, list.Data, 5)

	byName := map[string]*mqlAixSecurityPasswdEntry{}
	for _, x := range list.Data {
		e := x.(*mqlAixSecurityPasswdEntry)
		byName[e.Name.Data] = e
		// no field carries the hash
		for _, v := range []string{e.State.Data, e.HashAlgorithm.Data} {
			assert.False(t, strings.Contains(v, "xxxx") || strings.Contains(v, "XXXX"), e.Name.Data)
		}
	}

	assert.Equal(t, "empty", byName["root"].State.Data)
	assert.True(t, byName["root"].LastUpdate.IsNull())

	u := byName["mqluser1"]
	assert.Equal(t, "hashed", u.State.Data)
	assert.Equal(t, "ssha512", u.HashAlgorithm.Data)
	assert.Equal(t, []any{"ADMCHG"}, u.Flags.Data)
	assert.Equal(t, time.Unix(1791571248, 0).UTC(), *u.LastUpdate.Data)

	assert.Equal(t, []any{"ADMIN", "NOCHECK"}, byName["legacy"].Flags.Data)
	assert.Equal(t, "missing", byName["nopass"].State.Data)
}
