// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

// A group whose /etc/group entry names an account that does not resolve (a stale
// entry left behind by a deleted user, or a trailing comma in the member field)
// must still resolve group.members to the members it can resolve, rather than
// erroring the whole field with "cannot find user with name 'x'". Erroring it
// discards the entire member list, so every check reading group.members — such
// as "ensure the root group is empty" — fails on an otherwise compliant host.
func TestGroupMembers_UnresolvableMemberName(t *testing.T) {
	fixturePath, err := filepath.Abs("testdata/group_dangling_member.toml")
	require.NoError(t, err)

	asset := &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "centos",
			Family: []string{"linux", "unix"},
		},
	}
	conn, err := mock.New(0, asset, mock.WithPath(fixturePath))
	require.NoError(t, err)

	runtime := &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}

	raw, err := CreateResource(runtime, "groups", nil)
	require.NoError(t, err)
	groups := raw.(*mqlGroups)

	list := groups.GetList()
	require.NoError(t, list.Error)

	// /etc/group lists "ldapadmin,alice" for root; ldapadmin has no passwd entry.
	// root itself is a member via its primary gid.
	root, ok := groups.groupsByName["root"]
	require.True(t, ok, "root group must be present")

	members := root.GetMembers()
	require.NoError(t, members.Error, "group.members must not error on an unresolvable member name")

	names := make([]string, 0, len(members.Data))
	for i, m := range members.Data {
		user, ok := m.(*mqlUser)
		// A fix that keeps the pre-sized slice and skips leaves nil holes behind; report
		// that as a failure rather than panicking the package's test binary.
		require.True(t, ok, "member %d must be a user, got %#v", i, m)
		names = append(names, user.Name.Data)
	}

	// The unresolvable name is dropped, but every resolvable member is kept — a fix
	// that bailed out on the first miss would leave the list short or empty.
	assert.ElementsMatch(t, []string{"root", "alice"}, names)
}

// On Windows a group's members come with their SIDs. A member resolves to its
// user by SID, so a renamed account is still found, and a member that is not a
// local user (a domain group, a deleted account) is kept as a user with its
// name and SID instead of being dropped: a check over the Administrators group
// has to see it.
func TestGroupMembers_WindowsMembersBySid(t *testing.T) {
	fixturePath, err := filepath.Abs("testdata/group_dangling_member.toml")
	require.NoError(t, err)
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "centos", Family: []string{"linux", "unix"}},
	}, mock.WithPath(fixturePath))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}

	raw, err := CreateResource(runtime, "users", nil)
	require.NoError(t, err)
	list := raw.(*mqlUsers).GetList()
	require.NoError(t, list.Error)
	var alice *mqlUser
	for _, u := range list.Data {
		if u.(*mqlUser).Name.Data == "alice" {
			alice = u.(*mqlUser)
		}
	}
	require.NotNil(t, alice)
	alice.Sid = plugin.TValue[string]{Data: "S-1-5-21-1-2-3-500", State: plugin.StateIsSet}

	newGroup := func(name, sid string) *mqlGroup {
		raw, err := CreateResource(runtime, "group", map[string]*llx.RawData{
			"name": llx.StringData(name),
			"sid":  llx.StringData(sid),
			"gid":  llx.IntData(-1),
		})
		require.NoError(t, err)
		return raw.(*mqlGroup)
	}

	admins := newGroup("Administrators", "S-1-5-32-544")
	admins.membersArr = []string{`HOST\Administrator`, `CORP\Domain Admins`, "S-1-5-21-9-9-9-1105"}
	admins.memberSids = []string{"S-1-5-21-1-2-3-500", "S-1-5-21-5-5-5-512", "S-1-5-21-9-9-9-1105"}
	members := admins.GetMembers()
	require.NoError(t, members.Error)
	require.Len(t, members.Data, 3)

	// Resolved by SID: the local user's name differs from the member name.
	assert.Same(t, alice, members.Data[0])
	for i, want := range [][2]string{{`CORP\Domain Admins`, "S-1-5-21-5-5-5-512"}, {"S-1-5-21-9-9-9-1105", "S-1-5-21-9-9-9-1105"}} {
		u := members.Data[i+1].(*mqlUser)
		assert.Equal(t, want[0], u.Name.Data)
		assert.Equal(t, want[1], u.Sid.Data)
		assert.Equal(t, int64(-1), u.Uid.Data)
		assert.True(t, u.GetEnabled().IsNull(), "enabled is unknown for a member that is not a local user")
	}

	// Members that could not be read are an error, never an empty list.
	rdp := newGroup("Remote Desktop Users", "S-1-5-32-555")
	rdp.membersUnknown = true
	assert.Error(t, rdp.GetMembers().Error)
}
