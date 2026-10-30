// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package users_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers/os/resources/users"
)

func TestWindowsLocalUsersParser(t *testing.T) {
	data, err := os.Open("./testdata/windows.json")
	if err != nil {
		t.Fatal(err)
	}

	localUsers, err := users.ParseWindowsLocalUsers(data)
	assert.Nil(t, err)
	assert.Equal(t, 8, len(localUsers))

	expected := &users.WindowsLocalUser{
		Name:            "chris",
		Description:     "Built-in account for administering the computer/domain",
		PrincipalSource: 1,
		SID: users.WindowsSID{
			BinaryLength:     28,
			AccountDomainSid: new("S-1-5-21-2356735557-1575748656-448136971"),
			Value:            "S-1-5-21-2356735557-1575748656-448136971-500",
		},
		ObjectClass:            "User",
		Enabled:                true,
		FullName:               "",
		PasswordRequired:       true,
		UserMayChangePassword:  true,
		AccountExpires:         nil,
		PasswordChangeableDate: new("2020-04-15T20:11:59.9620000+00:00"),
		PasswordExpires:        new("2020-05-27T20:51:59.9620000+00:00"),
		PasswordLastSet:        new("2020-04-15T20:11:59.9620000+00:00"),
		LastLogon:              new("2020-04-16T14:55:59.0640000+00:00"),
		LocalPath:              `C:\Users\chris`,
	}
	found := findWindowsUser(localUsers, "chris")
	assert.EqualValues(t, expected, found)

	guest := findWindowsUser(localUsers, "Guest")
	assert.Equal(t, "", guest.LocalPath, "accounts without a profile registry entry have empty LocalPath")

	// Domain user synthesized from ProfileList alone (not present in Get-LocalUser).
	// Name comes from the ProfileImagePath leaf - no LSA call, just the on-disk
	// folder name, which matches what consumers iterating C:\Users\* actually want.
	jane := findWindowsUser(localUsers, "jane.doe")
	assert.NotNil(t, jane, "domain user from ProfileList should appear with path-leaf name")
	assert.Equal(t, 2, jane.PrincipalSource, "ActiveDirectory principal source for AD user")
	assert.Equal(t, `C:\Users\jane.doe`, jane.LocalPath)
	assert.True(t, jane.Enabled)

	// Entra ID (AAD) user - SID starts with S-1-12-1 and PrincipalSource is 3.
	// Name is the UPN harvested from the IdentityStore registry cache; the
	// on-disk folder uses a sanitized form (no @), which is why the two differ.
	bob := findWindowsUser(localUsers, "bob@example.com")
	assert.NotNil(t, bob, "AAD user should appear with UPN from IdentityStore cache")
	assert.Equal(t, 3, bob.PrincipalSource, "Azure AD principal source for S-1-12-1 SID")
	assert.Equal(t, `C:\Users\bob.example.com`, bob.LocalPath)

	// Orphan profile - whatever's still on disk. Name comes from the path leaf so
	// even SIDs we know nothing about surface with a recognizable label.
	orphan := findWindowsUser(localUsers, "orphan.user")
	assert.NotNil(t, orphan, "orphan profile should still appear with path-leaf name")
	assert.Equal(t, `C:\Users\orphan.user`, orphan.LocalPath)
}

func findWindowsUser(users []users.WindowsLocalUser, username string) *users.WindowsLocalUser {
	for i := range users {
		if users[i].Name == username {
			return &users[i]
		}
	}
	return nil
}
