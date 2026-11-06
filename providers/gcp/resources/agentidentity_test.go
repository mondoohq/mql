// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	agentidentity "google.golang.org/api/agentidentity/v1"
)

func TestAuthProviderType(t *testing.T) {
	cases := map[string]string{
		// Synthetic: one body per credential kind in the v1 discovery
		// document, secrets included to show they are never needed.
		`{"apiKey":{"apiKey":"AIza-secret"}}`:                                           "apiKey",
		`{"twoLeggedOauth":{"clientId":"c","clientSecret":"s","tokenUrl":"https://t"}}`: "twoLeggedOauth",
		`{"threeLeggedOauth":{"clientId":"c","clientSecret":"s"}}`:                      "threeLeggedOauth",
		`{"connectorReferenceAuthProvider":{"connector":"projects/p/locations/l/x"}}`:   "connectorReferenceAuthProvider",
		`{"geAuthProvider":{}}`:  "geAuthProvider",
		`{"xaaAuthProvider":{}}`: "xaaAuthProvider",
		`{}`:                     "",
	}
	for body, want := range cases {
		var p agentidentity.AuthProviderTypeParams
		require.NoError(t, json.Unmarshal([]byte(body), &p), body)
		assert.Equal(t, want, authProviderType(&p), body)
	}
	assert.Equal(t, "", authProviderType(nil))
}

func TestAuthProviderDecode(t *testing.T) {
	// Synthetic: an auth provider body shaped after the v1 discovery document.
	body := `{"name":"projects/p/locations/global/authProviders/jira","state":"ENABLED",
		"allowedScopes":["read:jira-work"],"blockedScopes":["write:jira-work"],
		"workloadIds":["w1"],"expireTime":"2027-01-01T00:00:00Z","deleted":false}`
	var ap agentidentity.AuthProvider
	require.NoError(t, json.Unmarshal([]byte(body), &ap))
	assert.Equal(t, "ENABLED", ap.State)
	assert.Equal(t, []string{"read:jira-work"}, ap.AllowedScopes)
	assert.Equal(t, []string{"write:jira-work"}, ap.BlockedScopes)
	assert.Equal(t, []string{"w1"}, ap.WorkloadIds)
	exp := parseTime(ap.ExpireTime)
	require.NotNil(t, exp)
	assert.Equal(t, 2027, exp.Year())
	// Synthetic: no expiry is null, not year 1.
	assert.Nil(t, parseTime(""))
}

func TestAgentIdentityBindingsToIampb(t *testing.T) {
	// Synthetic: a public binding, a conditional one and a nil entry.
	got := agentIdentityBindingsToIampb([]*agentidentity.Binding{
		{Role: "roles/agentidentity.user", Members: []string{"allAuthenticatedUsers"}},
		nil,
		{Role: "roles/agentidentity.admin", Members: []string{"group:a@example.com"}, Condition: &agentidentity.Expr{Title: "t", Expression: "e"}},
	})
	require.Len(t, got, 2)
	assert.Equal(t, []string{"allAuthenticatedUsers"}, got[0].Members)
	assert.Nil(t, got[0].Condition)
	require.NotNil(t, got[1].Condition)
	assert.Equal(t, "e", got[1].Condition.Expression)
}

func TestResourceNameWithoutProject(t *testing.T) {
	// Synthetic: project number and ID forms match.
	assert.Equal(t,
		resourceNameWithoutProject("projects/123/locations/global/authProviders/jira"),
		resourceNameWithoutProject("projects/my-proj/locations/global/authProviders/jira"))
	assert.Equal(t, "locations/global/authProviders/jira", resourceNameWithoutProject("projects/123/locations/global/authProviders/jira"))
	assert.Equal(t, "jira", resourceNameWithoutProject("jira"))
}
