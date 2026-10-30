// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package jboss_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/jboss"
)

// The hashes below are placeholders. No credential, real or realistic, is
// checked in: the parser only ever decides whether an entry carries one.
const notAHash = "EXAMPLE-NOT-A-REAL-HASH"

func TestParseUsers(t *testing.T) {
	users := `#
# Properties declaration of users for the realm 'ManagementRealm'
#
#$REALM_NAME=ManagementRealm$
admin=` + notAHash + `
operator=` + notAHash + `
service-account=
`
	roles := `#
admin=SuperUser
operator=Monitor,Deployer
`

	parsed := jboss.ParseUsers(users, roles)
	require.Len(t, parsed, 3)

	assert.Equal(t, "admin", parsed[0].Username)
	assert.True(t, parsed[0].HasPassword)
	assert.Equal(t, []string{"SuperUser"}, parsed[0].Roles)

	assert.Equal(t, "operator", parsed[1].Username)
	assert.Equal(t, []string{"Monitor", "Deployer"}, parsed[1].Roles)

	assert.Equal(t, "service-account", parsed[2].Username)
	assert.False(t, parsed[2].HasPassword, "an entry with no hash carries no password")
	assert.Empty(t, parsed[2].Roles)
	assert.NotNil(t, parsed[2].Roles, "a user with no roles has an empty list, not nil")
}

// add-user.sh escapes the characters the properties format reserves, so a
// user name containing one of them has to be unescaped to read as typed.
func TestParseUsersEscaping(t *testing.T) {
	users := `admin\=svc=` + notAHash + `
first\ last=` + notAHash + `
domain\:user=` + notAHash + `
`
	parsed := jboss.ParseUsers(users, "")
	require.Len(t, parsed, 3)
	assert.Equal(t, "admin=svc", parsed[0].Username)
	assert.Equal(t, "first last", parsed[1].Username)
	assert.Equal(t, "domain:user", parsed[2].Username)
}

func TestParseUsersSeparators(t *testing.T) {
	// A properties file accepts three separators and JBoss tooling has written
	// all of them over the years.
	parsed := jboss.ParseUsers("a="+notAHash+"\nb:"+notAHash+"\nc "+notAHash+"\n", "")
	require.Len(t, parsed, 3)
	for i, name := range []string{"a", "b", "c"} {
		assert.Equal(t, name, parsed[i].Username)
		assert.True(t, parsed[i].HasPassword)
	}
}

func TestParseUsersLineContinuation(t *testing.T) {
	parsed := jboss.ParseUsers("admin=EXAMPLE-\\\nNOT-A-REAL-HASH\n", "")
	require.Len(t, parsed, 1)
	assert.Equal(t, "admin", parsed[0].Username)
	assert.True(t, parsed[0].HasPassword)
}

func TestParseUsersIgnoresComments(t *testing.T) {
	parsed := jboss.ParseUsers("# admin=x\n! operator=y\n\n   \n", "")
	assert.Empty(t, parsed)
	assert.NotNil(t, parsed)
}

func TestParseUsersWithoutRolesFile(t *testing.T) {
	parsed := jboss.ParseUsers("admin="+notAHash+"\n", "")
	require.Len(t, parsed, 1)
	assert.Empty(t, parsed[0].Roles)
}
