// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

func TestParseLoggedInUsers(t *testing.T) {
	t.Run("windows sessions", func(t *testing.T) {
		out := " USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\n" +
			">mqladmin              rdp-tcp#0           2  Active          .  10/14/2026 9:12 AM\n" +
			" alice                                     3  Disc            5  10/14/2026 8:01 AM\n"
		users, err := parseLoggedInUsers(true, 0, out, "")
		require.NoError(t, err)
		assert.Equal(t, map[string]bool{"mqladmin": true, "alice": true}, users)
	})

	t.Run("windows nobody logged on", func(t *testing.T) {
		users, err := parseLoggedInUsers(true, 1, "", "No User exists for *\r\n")
		require.NoError(t, err)
		assert.Empty(t, users)
	})

	t.Run("windows nobody logged on, other display language", func(t *testing.T) {
		users, err := parseLoggedInUsers(true, 1, "", "Kein Benutzer für * vorhanden\r\n")
		require.NoError(t, err)
		assert.Empty(t, users)
	})

	t.Run("windows query.exe missing", func(t *testing.T) {
		_, err := parseLoggedInUsers(true, 9009, "",
			"'query' is not recognized as an internal or external command,\r\noperable program or batch file.\r\n")
		assert.ErrorContains(t, err, "not recognized")
	})

	t.Run("windows error that mentions a wildcard", func(t *testing.T) {
		_, err := parseLoggedInUsers(true, 1, "", "Error 0x000006BA enumerating sessions for C:/Users/*\r\n")
		assert.Error(t, err)
		_, err = parseLoggedInUsers(true, 1, "", "Error [5]: Access is denied.\r\nQuery for * failed\r\n")
		assert.Error(t, err)
	})

	t.Run("windows query fails", func(t *testing.T) {
		_, err := parseLoggedInUsers(true, 1, "", "Invalid parameter(s)\r\nQUERY { PROCESS | SESSION | TERMSERVER | USER }\r\n")
		assert.Error(t, err)
	})

	t.Run("who", func(t *testing.T) {
		users, err := parseLoggedInUsers(false, 0, "root     pts/0        2026-10-14 09:12 (10.0.0.1)\nalice    tty1         2026-10-14 08:01\n", "")
		require.NoError(t, err)
		assert.Equal(t, map[string]bool{"root": true, "alice": true}, users)
	})
}

// Windows users and groups have no numeric IDs and all report -1. A user's
// primary group must then be null, not whichever group has -1 and was listed
// first, and no user or group may be found under -1.
func TestUserGroup_WindowsHasNoPrimaryGroup(t *testing.T) {
	fixturePath, err := filepath.Abs("testdata/group_dangling_member.toml")
	require.NoError(t, err)
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "centos", Family: []string{"linux", "unix"}},
	}, mock.WithPath(fixturePath))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}

	raw, err := CreateResource(runtime, "groups", nil)
	require.NoError(t, err)
	groups := raw.(*mqlGroups)
	require.NoError(t, groups.GetList().Error)

	raw, err = CreateResource(runtime, "users", nil)
	require.NoError(t, err)
	users := raw.(*mqlUsers)
	require.NoError(t, users.GetList().Error)

	var winGroups []any
	for _, g := range [][2]string{{"Access Control Assistance Operators", "S-1-5-32-579"}, {"Administrators", "S-1-5-32-544"}} {
		raw, err := CreateResource(runtime, "group", map[string]*llx.RawData{
			"name": llx.StringData(g[0]),
			"sid":  llx.StringData(g[1]),
			"gid":  llx.IntData(-1),
		})
		require.NoError(t, err)
		winGroups = append(winGroups, raw)
	}
	require.NoError(t, groups.refreshCache(winGroups))

	raw, err = CreateResource(runtime, "user", map[string]*llx.RawData{
		"name":    llx.StringData("mqladmin"),
		"sid":     llx.StringData("S-1-5-21-1-2-3-500"),
		"uid":     llx.IntData(-1),
		"gid":     llx.IntData(-1),
		"home":    llx.StringData(`C:\Users\mqladmin`),
		"shell":   llx.StringData(""),
		"enabled": llx.BoolData(true),
	})
	require.NoError(t, err)
	admin := raw.(*mqlUser)
	require.NoError(t, users.refreshCache([]any{admin}))

	group := admin.GetGroup()
	require.NoError(t, group.Error)
	assert.True(t, group.IsNull(), "a Windows user has no primary group, got %v", group.Data)

	_, err = groups.findID(-1)
	var notFound resources.NotFoundError
	assert.True(t, errors.As(err, &notFound), "no group has gid -1, got %v", err)
	_, err = users.findID(-1)
	assert.True(t, errors.As(err, &notFound), "no user has uid -1, got %v", err)
}
