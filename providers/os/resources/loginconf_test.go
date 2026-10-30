// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func loginconfClasses(t *testing.T, platform, fixture string) map[string]*mqlLoginconfClass {
	t.Helper()
	rt := bsdRuntime(t, platform, "", fixture)
	raw, err := CreateResource(rt, "loginconf", map[string]*llx.RawData{})
	require.NoError(t, err)
	list := raw.(*mqlLoginconf).GetList()
	require.NoError(t, list.Error)
	res := map[string]*mqlLoginconfClass{}
	for _, x := range list.Data {
		c := x.(*mqlLoginconfClass)
		res[c.Name.Data] = c
	}
	return res
}

func TestLoginconfEdgeCases(t *testing.T) {
	classes := loginconfClasses(t, "freebsd", "edgecases.toml")
	assert.Len(t, classes, 7, "the second default record is hidden by the first")

	def := classes["default"]
	assert.Equal(t, []any{"Default Class"}, def.Aliases.Data)
	assert.Equal(t, "90d", def.Capabilities.Data.(map[string]any)["passwordtime"])
	assert.Equal(t, true, def.Capabilities.Data.(map[string]any)["requirehome"])
	assert.NotContains(t, def.Capabilities.Data.(map[string]any), "ignoretime")

	chain := classes["chain"]
	inh := chain.GetInherits()
	require.NoError(t, inh.Error)
	require.Len(t, inh.Data, 1)
	assert.Same(t, classes["middle"], inh.Data[0])
	assert.NotContains(t, chain.Capabilities.Data.(map[string]any), "tc")

	eff := chain.GetEffective()
	require.NoError(t, eff.Error)
	assert.Equal(t, "027", eff.Data.(map[string]any)["umask"])
	assert.Equal(t, "90d", eff.Data.(map[string]any)["passwordtime"])

	loop := classes["loopa"].GetEffective()
	require.Error(t, loop.Error)
	assert.True(t, errors.Is(loop.Error, llx.ErrMalformedData), loop.Error.Error())

	dangling := classes["dangling"]
	assert.Error(t, dangling.GetEffective().Error)
	assert.Error(t, dangling.GetInherits().Error)
}

func TestLoginconfClassInit(t *testing.T) {
	rt := bsdRuntime(t, "freebsd", "", "freebsd14.toml")

	_, res, err := initLoginconfClass(rt, map[string]*llx.RawData{"name": llx.StringData("Russian Users Accounts")})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "russian", res.(*mqlLoginconfClass).Name.Data, "lookups match aliases")

	_, _, err = initLoginconfClass(rt, map[string]*llx.RawData{"name": llx.StringData("nosuchclass")})
	require.Error(t, err)
	assert.True(t, errors.Is(err, llx.ErrNotFound))
}

func TestLoginconfFreeBSD14(t *testing.T) {
	classes := loginconfClasses(t, "freebsd", "freebsd14.toml")
	daemon := classes["daemon"].GetEffective()
	require.NoError(t, daemon.Error)
	assert.NotContains(t, daemon.Data.(map[string]any), "mail", "mail@ before tc=default")
	assert.Equal(t, "128M", daemon.Data.(map[string]any)["memorylocked"])
}
