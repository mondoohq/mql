// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

func TestDecodePersonalAccessTokenGranularScopes(t *testing.T) {
	// Synthetic: attribute names from the GitLab personal access tokens API for
	// one fine-grained token and one classic token. No target showed this.
	var tokens []*gitlab.PersonalAccessToken
	require.NoError(t, json.Unmarshal([]byte(`[
		{"id": 11, "name": "fine", "granular_scopes": [
			{"access": "selected_memberships", "permissions": ["read_code"], "project_id": 5, "group_id": null},
			{"access": "selected_memberships", "permissions": ["read_pipeline", "run_pipeline"], "project_id": null, "group_id": 9},
			{"access": "user", "permissions": ["read_user"]}
		]},
		{"id": 12, "name": "classic", "scopes": ["api"]}
	]`), &tokens))
	require.Len(t, tokens, 2)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	scopes, err := newGranularScopes(runtime, tokens[0].ID, tokens[0].GranularScopes)
	require.NoError(t, err)
	require.Len(t, scopes, 3)

	first := scopes[0].(*mqlGitlabGranularScope)
	assert.Equal(t, "selected_memberships", first.Access.Data)
	assert.Equal(t, []any{"read_code"}, first.Permissions.Data)
	assert.EqualValues(t, 5, first.cacheProjectID)
	assert.Zero(t, first.cacheGroupID)

	second := scopes[1].(*mqlGitlabGranularScope)
	assert.Equal(t, []any{"read_pipeline", "run_pipeline"}, second.Permissions.Data)
	assert.Zero(t, second.cacheProjectID)
	assert.EqualValues(t, 9, second.cacheGroupID)

	third := scopes[2].(*mqlGitlabGranularScope)
	assert.Equal(t, "user", third.Access.Data)
	assert.Zero(t, third.cacheProjectID)
	assert.Zero(t, third.cacheGroupID)

	classic, err := granularScopesData(runtime, tokens[1].ID, tokens[1].GranularScopes)
	require.NoError(t, err)
	assert.Nil(t, classic.Value, "a classic token must read null, not an empty scope list")
}

func TestGranularScopeIDsDistinguishTokens(t *testing.T) {
	// Synthetic: two tokens whose scopes are identical. Each scope must stay a
	// separate resource, or the second token reports the first one's targets.
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	project := int64(5)
	other := int64(6)

	a, err := newGranularScopes(runtime, 11, []*gitlab.GranularScope{{Access: "selected_memberships", ProjectID: &project}})
	require.NoError(t, err)
	b, err := newGranularScopes(runtime, 12, []*gitlab.GranularScope{{Access: "selected_memberships", ProjectID: &other}})
	require.NoError(t, err)

	require.Len(t, a, 1)
	require.Len(t, b, 1)
	assert.NotSame(t, a[0], b[0])
	assert.EqualValues(t, 5, a[0].(*mqlGitlabGranularScope).cacheProjectID)
	assert.EqualValues(t, 6, b[0].(*mqlGitlabGranularScope).cacheProjectID)
	assert.NotEqual(t, granularScopeID(11, 0), granularScopeID(11, 1))
}

func TestUserScimIdentitiesAndCommitEmail(t *testing.T) {
	newUser := func(t *testing.T, status int, body string) *mqlGitlabUser {
		t.Helper()
		runtime := newTestGroupRuntime(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v4/users/10", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			fmt.Fprint(w, body)
		}))
		res, err := CreateResource(runtime, "gitlab.user", map[string]*llx.RawData{"id": llx.IntData(10)})
		require.NoError(t, err)
		return res.(*mqlGitlabUser)
	}

	// Synthetic: an administrator reading a user provisioned into two
	// top-level groups by the same identity provider, so the external id
	// repeats. No target showed this.
	u := newUser(t, http.StatusOK, `{"id": 10, "commit_email": "dev@example.com", "scim_identities": [
		{"extern_uid": "okta|00u1", "group_id": 1, "active": true},
		{"extern_uid": "okta|00u1", "group_id": 2, "active": false}
	]}`)
	assert.Equal(t, "dev@example.com", u.GetCommitEmail().Data)
	identities := u.GetScimIdentities()
	require.NoError(t, identities.Error)
	require.Len(t, identities.Data, 2)
	first := identities.Data[0].(*mqlGitlabGroupScimIdentity)
	second := identities.Data[1].(*mqlGitlabGroupScimIdentity)
	assert.NotSame(t, first, second, "the same external id in two groups is two identities")
	assert.EqualValues(t, 1, first.groupID)
	assert.True(t, first.Active.Data)
	assert.EqualValues(t, 2, second.groupID)
	assert.False(t, second.Active.Data)
	assert.EqualValues(t, 10, second.cacheUserID)

	// Synthetic: a token that cannot read the user.
	denied := newUser(t, http.StatusForbidden, `{"message": "403 Forbidden"}`)
	email := denied.GetCommitEmail()
	require.NoError(t, email.Error)
	assert.NotZero(t, email.State&plugin.StateIsNull, "an unreadable commit email must read null, not empty")
	denied2 := denied.GetScimIdentities()
	require.NoError(t, denied2.Error)
	assert.NotZero(t, denied2.State&plugin.StateIsNull, "unreadable identities must read null, not an empty list")
}
