// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func aixSecurityLimit(t *testing.T, name string) *mqlAixSecurityLimit {
	t.Helper()
	rt := newAixRuntime(t, aixPlatform, map[string]string{
		"/etc/security/limits": "aix/testdata/limits_aix73.txt",
	}, nil)
	r, err := NewResource(rt, "aix.security.limit", map[string]*llx.RawData{"name": llx.StringData(name)})
	require.NoError(t, err)
	return r.(*mqlAixSecurityLimit)
}

func TestAixSecurityLimit(t *testing.T) {
	// esaadmin sets its stack limits, the rest comes from default
	esa := aixSecurityLimit(t, "esaadmin")
	assert.Equal(t, int64(393216), esa.Stack.Data)
	assert.Equal(t, int64(393216), esa.StackHard.Data)
	assert.Equal(t, int64(2097151), esa.Core.Data, "inherited")
	assert.Equal(t, int64(-1), esa.Fsize.Data, "unlimited")

	// neither stanza sets core_hard
	root := aixSecurityLimit(t, "root")
	assert.True(t, root.CoreHard.IsNull())
	assert.Equal(t, int64(2000), root.Nofiles.Data)
}
