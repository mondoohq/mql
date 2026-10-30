// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/resources/aix"
)

func aixSecurityUser(t *testing.T, name string) *mqlAixSecurityUser {
	t.Helper()
	rt := newAixRuntime(t, aixPlatform, map[string]string{
		"/etc/security/user": "aix/testdata/security_user_aix73.txt",
	}, nil)
	r, err := NewResource(rt, "aix.security.user", map[string]*llx.RawData{"name": llx.StringData(name)})
	require.NoError(t, err)
	return r.(*mqlAixSecurityUser)
}

func TestAixSecurityUserInheritsDefault(t *testing.T) {
	// root's stanza sets minlen and loginretries, the rest comes from default
	root := aixSecurityUser(t, "root")
	assert.Equal(t, int64(15), root.Minlen.Data)
	assert.Equal(t, int64(13), root.Maxage.Data, "inherited")
	assert.True(t, root.Admin.Data)
	assert.True(t, root.Rlogin.Data, "inherited")
	assert.Equal(t, "compat", root.AuthSystem.Data)
	assert.NotContains(t, root.Explicit.Data, "maxage")
	assert.Equal(t, "15", root.Explicit.Data["minlen"])

	uucp := aixSecurityUser(t, "uucp")
	assert.False(t, uucp.Login.Data)
	assert.False(t, uucp.Rlogin.Data)
	assert.Equal(t, int64(10), uucp.Minlen.Data, "inherited")
	assert.Equal(t, []any{"ALL"}, uucp.Sugroups.Data)
}

// A user in /etc/passwd without a stanza of its own inherits every
// attribute, as lsuser reports it.
func TestAixSecurityUserWithoutStanza(t *testing.T) {
	u := aixSecurityUser(t, "nostanza")
	assert.Equal(t, int64(13), u.Maxage.Data)
	assert.Equal(t, map[string]any{}, u.Explicit.Data)
}

// daemon sets its own expiry date; root inherits the default stanza's 0.
func TestAixSecurityUserExpires(t *testing.T) {
	assert.Equal(t, "0101000070", aixSecurityUser(t, "daemon").Expires.Data)
	assert.Equal(t, "0", aixSecurityUser(t, "root").Expires.Data)
	// neither the default stanza nor uucp's sets a registry
	assert.True(t, aixSecurityUser(t, "uucp").Registry.IsNull())
}

func TestAixSecurityUsersList(t *testing.T) {
	rt := newAixRuntime(t, aixPlatform, map[string]string{
		"/etc/security/user": "aix/testdata/security_user_aix73.txt",
	}, nil)
	r, err := CreateResource(rt, "aix.security.users", map[string]*llx.RawData{})
	require.NoError(t, err)
	users := r.(*mqlAixSecurityUsers)
	list := users.GetList()
	require.NoError(t, list.Error)
	// every user of /etc/passwd, nostanza included
	assert.Len(t, list.Data, 6)
	defaults := users.GetDefaults()
	require.NoError(t, defaults.Error)
	assert.Equal(t, "13", defaults.Data["maxage"])
}

func TestAixSecurityUserUserReference(t *testing.T) {
	root := aixSecurityUser(t, "root")
	u := root.GetUser()
	require.NoError(t, u.Error)
	require.NotNil(t, u.Data)
	assert.Equal(t, int64(0), u.Data.Uid.Data)
}

func TestAixSecurityUsersNotApplicableOffAix(t *testing.T) {
	linux := &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}
	rt := newAixRuntime(t, linux, nil, nil)
	r, err := CreateResource(rt, "aix.security.users", map[string]*llx.RawData{})
	require.NoError(t, err)
	list := r.(*mqlAixSecurityUsers).GetList()
	require.Error(t, list.Error)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(list.Error))
}

// A stanza file whose default stanza sets no sugroups leaves the field null:
// AIX then applies its built-in ALL, which an empty list would contradict.
func TestAixSecurityUserUnsetSugroupsIsNull(t *testing.T) {
	st, err := aix.ParseStanzas(strings.NewReader("default:\n\tminlen = 8\nuser1:\n\tmaxage = 4\n"))
	require.NoError(t, err)
	u, err := newAixSecurityUser(newAixRuntime(t, aixPlatform, nil, nil), st, "user1")
	require.NoError(t, err)
	assert.True(t, u.Sugroups.IsNull())
	assert.Equal(t, int64(8), u.Minlen.Data)
}
