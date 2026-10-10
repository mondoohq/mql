// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestAixSecurityLoginCfg(t *testing.T) {
	rt := newAixRuntime(t, aixPlatform, map[string]string{
		"/etc/security/login.cfg": "aix/testdata/login_cfg_aix73.txt",
	}, nil)
	r, err := CreateResource(rt, "aix.security.loginCfg", map[string]*llx.RawData{})
	require.NoError(t, err)
	l := r.(*mqlAixSecurityLoginCfg)

	assert.Equal(t, "ssha256", l.GetPwdAlgorithm().Data)
	assert.Equal(t, "STD_AUTH", l.GetAuthType().Data)
	assert.Equal(t, int64(32767), l.GetMaxlogins().Data)
	assert.Equal(t, int64(60), l.GetLogintimeout().Data)
	assert.Equal(t, int64(0), l.GetLogindisable().Data)
	assert.False(t, l.GetSakEnabled().Data)
	shells := l.GetShells()
	require.NoError(t, shells.Error)
	assert.Len(t, shells.Data, 18)
	assert.Contains(t, shells.Data, "/usr/bin/ksh")

	// the default stanza sets no herald
	assert.True(t, l.GetHerald().IsNull())
	stanzas := l.GetStanzas()
	require.NoError(t, stanzas.Error)
	assert.Contains(t, stanzas.Data, "usw")
}

func TestAixSecurityLoginCfgUnsetIntIsNull(t *testing.T) {
	rt := newAixRuntime(t, aixPlatform, map[string]string{
		"/etc/security/login.cfg": "aix/testdata/login_cfg_aix73.txt",
	}, nil)
	r, err := CreateResource(rt, "aix.security.loginCfg", map[string]*llx.RawData{})
	require.NoError(t, err)
	l := r.(*mqlAixSecurityLoginCfg)
	// drop attributes from the parsed file to read ones that are not there
	_, err = l.load()
	require.NoError(t, err)
	delete(l.parsed.Get("usw").Attrs, "maxlogins")
	delete(l.parsed.Get("usw").Attrs, "shells")
	m := l.GetMaxlogins()
	require.NoError(t, m.Error)
	assert.True(t, m.IsNull())
	shells := l.GetShells()
	require.NoError(t, shells.Error)
	assert.True(t, shells.IsNull())
}
