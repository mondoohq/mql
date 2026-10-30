// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package groups

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// The shape getLocalGroupsScript prints, with a local member, a domain member,
// a well-known principal and an orphaned SID (a deleted account, whose ADsPath
// is only the SID).
const groupsWithMembersJSON = `[
  {
    "Name": "Administrators",
    "Description": "Administrators have complete and unrestricted access to the computer/domain",
    "PrincipalSource": 1,
    "ObjectClass": "Group",
    "SID": {"BinaryLength": 16, "AccountDomainSid": null, "Value": "S-1-5-32-544"},
    "Members": [
      {"Sid": "S-1-5-21-1111111111-2222222222-3333333333-500", "Name": "HOST\\Administrator"},
      {"Sid": "S-1-5-21-4444444444-5555555555-6666666666-512", "Name": "CORP\\Domain Admins"},
      {"Sid": "S-1-5-21-1111111111-2222222222-3333333333-1005", "Name": "S-1-5-21-1111111111-2222222222-3333333333-1005"}
    ],
    "MembersError": false
  },
  {
    "Name": "Users",
    "Description": "Users are prevented from making accidental or intentional system-wide changes",
    "PrincipalSource": 1,
    "ObjectClass": "Group",
    "SID": {"BinaryLength": 16, "AccountDomainSid": null, "Value": "S-1-5-32-545"},
    "Members": {"Sid": "S-1-5-4", "Name": "NT AUTHORITY\\INTERACTIVE"},
    "MembersError": false
  },
  {
    "Name": "Remote Desktop Users",
    "Description": "",
    "PrincipalSource": 1,
    "ObjectClass": "Group",
    "SID": {"BinaryLength": 16, "AccountDomainSid": null, "Value": "S-1-5-32-555"},
    "Members": [],
    "MembersError": true
  }
]`

func TestParseWindowsLocalGroupsWithMembers(t *testing.T) {
	gs, err := ParseWindowsLocalGroups(strings.NewReader(groupsWithMembersJSON))
	require.NoError(t, err)
	require.Len(t, gs, 3)

	admins := winToGroup(gs[0])
	assert.Equal(t, "S-1-5-32-544", admins.Sid)
	assert.Equal(t, []string{
		`HOST\Administrator`,
		`CORP\Domain Admins`,
		"S-1-5-21-1111111111-2222222222-3333333333-1005",
	}, admins.Members)
	assert.Equal(t, []string{
		"S-1-5-21-1111111111-2222222222-3333333333-500",
		"S-1-5-21-4444444444-5555555555-6666666666-512",
		"S-1-5-21-1111111111-2222222222-3333333333-1005",
	}, admins.MemberSids)
	assert.False(t, admins.MembersUnknown)

	// ConvertTo-Json prints a group with one member as an object, not a list.
	users := winToGroup(gs[1])
	assert.Equal(t, []string{`NT AUTHORITY\INTERACTIVE`}, users.Members)
	assert.Equal(t, []string{"S-1-5-4"}, users.MemberSids)

	// Members that could not be read are unknown, not an empty group.
	rdp := winToGroup(gs[2])
	assert.Empty(t, rdp.Members)
	assert.True(t, rdp.MembersUnknown)
}

// A member without a name (the native path leaves it empty for a deleted
// account) is named by its SID.
func TestWinToGroupNamesMemberBySid(t *testing.T) {
	g := winToGroup(WindowsLocalGroup{
		Name:    "Administrators",
		SID:     WindowsSID{Value: "S-1-5-32-544"},
		Members: []WindowsGroupMember{{Sid: "S-1-5-21-1-2-3-1005"}},
	})
	assert.Equal(t, []string{"S-1-5-21-1-2-3-1005"}, g.Members)
}

// The command has to fit a Windows command line when encoded; groups are one
// PowerShell process, so the script is not staged.
func TestGetLocalGroupsCommandFitsCommandLine(t *testing.T) {
	assert.LessOrEqual(t, len(GetLocalGroupsCommand()), powershell.MaxCommandLength)
}
