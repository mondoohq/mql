// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/portainer/client-api-go/v2/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/portainer/connection"
)

func TestUnixTimePtr(t *testing.T) {
	// 0 means "unset" and must map to null (nil) rather than the 1970 epoch.
	assert.Nil(t, unixTimePtr(0))

	got := unixTimePtr(1700000000)
	require.NotNil(t, got)
	assert.Equal(t, int64(1700000000), got.Unix())
	assert.Equal(t, "UTC", got.Location().String())
}

func TestSecuritySettingsToDict(t *testing.T) {
	// nil overrides -> nil dict (field resolves to an empty dict).
	assert.Nil(t, securitySettingsToDict(nil))

	got := securitySettingsToDict(&models.PortainerEndpointSecuritySettings{
		AllowPrivilegedModeForRegularUsers: true,
		AllowSysctlSettingForRegularUsers:  true,
	})
	require.NotNil(t, got)
	assert.Equal(t, true, got["allowPrivilegedModeForRegularUsers"])
	assert.Equal(t, true, got["allowSysctlSettingForRegularUsers"])
	assert.Equal(t, false, got["allowBindMountsForRegularUsers"])
	// every documented override should be present
	assert.Len(t, got, 9)
}

func TestAccessPoliciesToDict(t *testing.T) {
	got := accessPoliciesToDict(map[string]models.PortainerAccessPolicy{
		"5": {RoleID: 1},
		"8": {RoleID: 3},
	})
	assert.Equal(t, int64(1), got["5"])
	assert.Equal(t, int64(3), got["8"])

	assert.Empty(t, accessPoliciesToDict(nil))
}

func TestAccessRolesToDict(t *testing.T) {
	got := accessRolesToDict(map[string]models.PortainerAccessPolicy{
		"5": {RoleID: 1},
		"8": {RoleID: 4},
		"9": {RoleID: 42},
	})
	assert.Equal(t, "environment_administrator", got["5"])
	assert.Equal(t, "readonly_user", got["8"])
	assert.Equal(t, "unknown", got["9"])

	assert.Empty(t, accessRolesToDict(nil))
}

// TestTLSConfig is a regression test: the endpoint's top-level TLS field has
// been deprecated since Portainer's DBVersion 4 and is no longer written by the
// server, so reading it reported "no TLS" for every environment. The live
// values come from TLSConfig.
func TestTLSConfig(t *testing.T) {
	// the deprecated top-level field must not be consulted
	enabled, skip := tlsConfig(&models.PortainereeEndpoint{TLS: true})
	assert.False(t, enabled, "deprecated TLS field must be ignored")
	assert.False(t, skip)

	enabled, skip = tlsConfig(&models.PortainereeEndpoint{
		TLSConfig: &models.PortainerTLSConfiguration{TLS: true, TLSSkipVerify: true},
	})
	assert.True(t, enabled)
	assert.True(t, skip)

	enabled, skip = tlsConfig(&models.PortainereeEndpoint{
		TLSConfig: &models.PortainerTLSConfiguration{TLS: true},
	})
	assert.True(t, enabled)
	assert.False(t, skip)

	// a missing TLSConfig is a plaintext connection, not a panic
	enabled, skip = tlsConfig(&models.PortainereeEndpoint{})
	assert.False(t, enabled)
	assert.False(t, skip)
}

// TestUserTheme covers the deprecated UserTheme field being superseded by
// ThemeSettings.
func TestUserTheme(t *testing.T) {
	assert.Equal(t, "dark", userTheme(&models.PortainereeUser{
		ThemeSettings: &models.PortainereeUserThemeSettings{Color: "dark"},
		UserTheme:     "light",
	}), "ThemeSettings wins over the deprecated field")

	assert.Equal(t, "light", userTheme(&models.PortainereeUser{UserTheme: "light"}),
		"falls back to the legacy field when ThemeSettings is absent")

	assert.Equal(t, "light", userTheme(&models.PortainereeUser{
		ThemeSettings: &models.PortainereeUserThemeSettings{},
		UserTheme:     "light",
	}), "an empty ThemeSettings color falls back too")

	assert.Empty(t, userTheme(&models.PortainereeUser{}))
}

// TestUserTeams is a regression test: a membership pointing at a team the token
// cannot see used to yield a team with an empty name, which also poisoned the
// resource cache for that team id.
func TestUserTeams(t *testing.T) {
	teams := []*models.PortainerTeam{
		{ID: 1, Name: "platform"},
		{ID: 2, Name: "security"},
	}
	memberships := []*models.PortainerTeamMembership{
		{ID: 10, UserID: 100, TeamID: 1, Role: 1},
		{ID: 11, UserID: 100, TeamID: 2, Role: 2},
		{ID: 12, UserID: 101, TeamID: 2, Role: 2},
		// dangling: team 99 is not visible to this token
		{ID: 13, UserID: 100, TeamID: 99, Role: 2},
	}

	got := userTeams(memberships, teams, 100)
	require.Len(t, got, 2, "the dangling membership must be skipped")
	assert.Equal(t, "platform", got[0].Name)
	assert.Equal(t, "security", got[1].Name)

	assert.Len(t, userTeams(memberships, teams, 101), 1)
	assert.Empty(t, userTeams(memberships, teams, 999))
}

func TestTeamMembers(t *testing.T) {
	users := []*models.PortainereeUser{
		{ID: 100, Username: "alice"},
		{ID: 101, Username: "bob"},
	}
	memberships := []*models.PortainerTeamMembership{
		{ID: 10, UserID: 100, TeamID: 1, Role: 1},
		{ID: 11, UserID: 101, TeamID: 1, Role: 2},
		{ID: 12, UserID: 100, TeamID: 2, Role: 2},
		// dangling: user 999 is not visible to this token
		{ID: 13, UserID: 999, TeamID: 1, Role: 2},
	}

	got := teamMembers(memberships, users, 1)
	require.Len(t, got, 2, "the dangling membership must be skipped")
	assert.Equal(t, "alice", got[0].Username)
	assert.Equal(t, "bob", got[1].Username)

	assert.Len(t, teamMembers(memberships, users, 2), 1)
	assert.Empty(t, teamMembers(memberships, users, 3))
}

// TestTeamMemberRoles covers the leader/member split, which the membership role
// carries and which nothing surfaced before.
func TestTeamMemberRoles(t *testing.T) {
	users := []*models.PortainereeUser{
		{ID: 100, Username: "alice"},
		{ID: 101, Username: "bob"},
	}
	memberships := []*models.PortainerTeamMembership{
		{ID: 10, UserID: 100, TeamID: 1, Role: 1},
		{ID: 11, UserID: 101, TeamID: 1, Role: 2},
		{ID: 12, UserID: 999, TeamID: 1, Role: 2},
	}

	got := teamMemberRoles(memberships, users, 1)
	assert.Equal(t, map[string]any{"alice": "leader", "bob": "member"}, got)

	assert.Empty(t, teamMemberRoles(memberships, users, 2))
}

func TestMatchesEnvironmentTargets(t *testing.T) {
	const (
		dockerType = int64(1) // docker
		k8sType    = int64(5) // kubernetes
		edgeType   = int64(4) // edge-agent-docker
	)

	cases := []struct {
		name    string
		targets []string
		envType int64
		want    bool
	}{
		{"auto matches docker", []string{connection.DiscoveryAuto}, dockerType, true},
		{"all matches kubernetes", []string{connection.DiscoveryAll}, k8sType, true},
		{"environments matches edge", []string{connection.DiscoveryEnvironments}, edgeType, true},
		{"docker target matches docker", []string{connection.DiscoveryDocker}, dockerType, true},
		{"docker target rejects kubernetes", []string{connection.DiscoveryDocker}, k8sType, false},
		{"kubernetes target matches kubernetes", []string{connection.DiscoveryKubernetes}, k8sType, true},
		{"edge target matches edge", []string{connection.DiscoveryEdge}, edgeType, true},
		{"edge target rejects plain docker", []string{connection.DiscoveryEdge}, dockerType, false},
		{"no targets matches nothing", []string{}, dockerType, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, matchesEnvironmentTargets(tc.targets, tc.envType))
		})
	}
}
