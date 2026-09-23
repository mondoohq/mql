// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/google/go-github/v92/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoginSet(t *testing.T) {
	set := loginSet([]*github.User{
		{Login: github.Ptr("alice")},
		{Login: github.Ptr("bob")},
		// A user with no login must not panic, and must not be mistaken for a
		// real member later.
		{},
	})

	assert.Contains(t, set, "alice")
	assert.Contains(t, set, "bob")
	assert.NotContains(t, set, "carol")
	assert.Contains(t, set, "", "a nil login indexes as the empty string")
}

func TestMembershipRole(t *testing.T) {
	admins := loginSet([]*github.User{{Login: github.Ptr("alice")}})

	t.Run("listed as an owner", func(t *testing.T) {
		got := membershipRole("alice", admins, true)
		require.NotNil(t, got)
		assert.Equal(t, "admin", *got)
	})

	t.Run("absent from the owner list", func(t *testing.T) {
		got := membershipRole("bob", admins, true)
		require.NotNil(t, got)
		assert.Equal(t, "member", *got)
	})

	t.Run("an organization with no owners we can see", func(t *testing.T) {
		got := membershipRole("bob", nil, true)
		require.NotNil(t, got)
		assert.Equal(t, "member", *got)
	})

	t.Run("unreadable owner list stays unknown", func(t *testing.T) {
		// Reporting "member" here would understate the access of an owner we
		// were simply not allowed to see.
		assert.Nil(t, membershipRole("alice", admins, false))
		assert.Nil(t, membershipRole("bob", nil, false))
	})
}

func TestMembershipTwoFactorEnabled(t *testing.T) {
	without2FA := loginSet([]*github.User{{Login: github.Ptr("bob")}})

	t.Run("listed as lacking 2FA reports false", func(t *testing.T) {
		got := membershipTwoFactorEnabled("bob", without2FA, true)
		require.NotNil(t, got)
		assert.False(t, *got)
	})

	t.Run("absent from the list reports true", func(t *testing.T) {
		got := membershipTwoFactorEnabled("alice", without2FA, true)
		require.NotNil(t, got)
		assert.True(t, *got)
	})

	t.Run("unreadable state stays unknown", func(t *testing.T) {
		// The token could not list members lacking 2FA. Reporting true here
		// would assert that every member has 2FA on the strength of an empty
		// list we were never allowed to read.
		assert.Nil(t, membershipTwoFactorEnabled("alice", nil, false))
		assert.Nil(t, membershipTwoFactorEnabled("bob", without2FA, false))
	})
}

func TestTeamPermissionLevels(t *testing.T) {
	tests := []struct {
		name        string
		permissions map[string]bool
		expected    []string
	}{
		{
			name:        "admin grant satisfies every level",
			permissions: map[string]bool{"admin": true, "maintain": true, "push": true, "triage": true, "pull": true},
			expected:    []string{"admin", "maintain", "push", "triage", "pull"},
		},
		{
			name:        "push grant",
			permissions: map[string]bool{"admin": false, "maintain": false, "push": true, "triage": true, "pull": true},
			expected:    []string{"push", "triage", "pull"},
		},
		{
			name:        "read-only grant",
			permissions: map[string]bool{"admin": false, "maintain": false, "push": false, "triage": false, "pull": true},
			expected:    []string{"pull"},
		},
		{
			name:        "unknown levels are ignored",
			permissions: map[string]bool{"pull": true, "some_future_level": true},
			expected:    []string{"pull"},
		},
		{
			name:        "no permissions reported",
			permissions: nil,
			expected:    []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, teamPermissionLevels(test.permissions))
		})
	}
}
