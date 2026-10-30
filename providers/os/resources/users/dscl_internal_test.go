// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package users

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// The dscl lists are fetched independently, so a later list (e.g. UserShell)
// can contain a record that the UniqueID list did not. List() must not panic
// when indexing the user map for such a key.
func TestOSXUserManagerList_SkewedLists(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"dscl . -list /Users UniqueID": {
				Stdout: "root 0\n_www 70\n",
			},
			// UserShell lists an extra user `ghost` that is absent from UniqueID.
			"dscl . -list /Users UserShell": {
				Stdout: "root /bin/sh\n_www /usr/bin/false\nghost /bin/zsh\n",
			},
			"dscl . -list /Users NFSHomeDirectory": {
				Stdout: "root /var/root\n_www /Library/WebServer\n",
			},
			"dscl . -list /Users RealName": {
				Stdout: "root System Administrator\n_www World Wide Web Server\n",
			},
			"dscl . -list /Users PrimaryGroupID": {
				Stdout: "root 0\n_www 70\n",
			},
			"dscl . -list /Users AuthenticationAuthority": {
				Stdout: "_www ;ShadowHash;\nghost ;ShadowHash;\n",
			},
		},
	}))
	require.NoError(t, err)

	mgr := &OSXUserManager{conn: conn}

	var list []*User
	require.NotPanics(t, func() {
		list, err = mgr.List()
	})
	require.NoError(t, err)

	// Only the users present in the UniqueID list are materialized; the extra
	// `ghost` shell entry is ignored rather than panicking.
	require.Len(t, list, 2)

	byName := map[string]*User{}
	for _, u := range list {
		byName[u.Name] = u
	}
	require.Contains(t, byName, "root")
	require.Contains(t, byName, "_www")
	require.NotContains(t, byName, "ghost")

	assert.Equal(t, "/usr/bin/false", byName["_www"].Shell)
	assert.Equal(t, "/Library/WebServer", byName["_www"].Home)
	assert.Equal(t, int64(70), byName["_www"].Gid)
	assert.True(t, byName["_www"].Enabled)
	assert.False(t, byName["root"].Enabled)
}

func TestDsclAuthorityEnabled(t *testing.T) {
	tests := []struct {
		name      string
		authority string
		want      bool
	}{
		{name: "empty", authority: "", want: false},
		{name: "whitespace", authority: "   ", want: false},
		{name: "shadow hash", authority: ";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2> ;SecureToken;", want: true},
		{name: "disabled before shadow hash", authority: ";DisabledUser;;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>", want: false},
		{name: "disabled only", authority: ";DisabledUser;", want: false},
		{name: "kerberos", authority: ";Kerberosv5;;alice@LKDC:SHA1.0000;LKDC:SHA1.0000;", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, dsclAuthorityEnabled(tt.authority))
		})
	}
}
