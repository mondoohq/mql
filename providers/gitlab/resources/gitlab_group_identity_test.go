// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestAccessRequestsStayScopedToTheirGroup(t *testing.T) {
	// Synthetic: one user asking to join two groups. AccessRequest.ID is the
	// user id, so both requests carry id 10 and only the group tells them
	// apart. No target showed this.
	runtime := newTestGroupRuntime(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/groups/1/access_requests":
			fmt.Fprint(w, `[{"id": 10, "username": "dev", "state": "awaiting"}]`)
		case "/api/v4/groups/2/access_requests":
			fmt.Fprint(w, `[{"id": 10, "username": "dev", "state": "active"}]`)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	requests := func(id int64) *mqlGitlabGroupAccessRequest {
		g, err := CreateResource(runtime, "gitlab.group", map[string]*llx.RawData{"id": llx.IntData(id), "name": llx.StringData("g"), "path": llx.StringData("g")})
		require.NoError(t, err)
		list := g.(*mqlGitlabGroup).GetAccessRequests()
		require.NoError(t, list.Error)
		require.Len(t, list.Data, 1)
		return list.Data[0].(*mqlGitlabGroupAccessRequest)
	}

	first := requests(1)
	second := requests(2)
	assert.NotSame(t, first, second)
	assert.Equal(t, "awaiting", first.State.Data)
	assert.Equal(t, "active", second.State.Data, "the second group's request must not resolve to the first one's")
	assert.EqualValues(t, 1, first.groupID)
	assert.EqualValues(t, 2, second.groupID)
}

func TestScimIdentitiesWithoutExternalIDStayDistinct(t *testing.T) {
	// Synthetic: an identity provider that reports an empty extern_uid for two
	// members of the same group. No target showed this.
	runtime := newTestGroupRuntime(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		assert.Equal(t, "/api/v4/groups/1/scim/identities", r.URL.Path)
		fmt.Fprint(w, `[{"extern_uid": "", "user_id": 10, "active": true}, {"extern_uid": "", "user_id": 20, "active": false}]`)
	}))

	g, err := CreateResource(runtime, "gitlab.group", map[string]*llx.RawData{"id": llx.IntData(1), "name": llx.StringData("g"), "path": llx.StringData("g")})
	require.NoError(t, err)
	list := g.(*mqlGitlabGroup).GetScimIdentities()
	require.NoError(t, list.Error)
	require.Len(t, list.Data, 2)

	first := list.Data[0].(*mqlGitlabGroupScimIdentity)
	second := list.Data[1].(*mqlGitlabGroupScimIdentity)
	assert.NotSame(t, first, second)
	assert.True(t, first.Active.Data)
	assert.False(t, second.Active.Data)
	assert.EqualValues(t, 10, first.cacheUserID)
	assert.EqualValues(t, 20, second.cacheUserID)
}
