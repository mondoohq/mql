// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestListGroupMemberRolesWalksPagesByPath(t *testing.T) {
	// Synthetic: two pages of custom roles under a top-level group path; no
	// target showed this.
	var paths []string
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.EscapedPath()+"?page="+r.URL.Query().Get("page"))
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") == "2" {
			fmt.Fprint(w, `[{"id": 9, "name": "Release manager", "base_access_level": 30}]`)
			return
		}
		w.Header().Set("X-Next-Page", "2")
		fmt.Fprint(w, `[{"id": 7, "name": "Security reviewer", "base_access_level": 20}]`)
	}))

	roles, err := listGroupMemberRoles(client, "acme")
	require.NoError(t, err)
	require.Len(t, roles, 2)
	assert.EqualValues(t, 7, roles[0].ID)
	assert.EqualValues(t, 9, roles[1].ID)
	assert.EqualValues(t, 30, roles[1].BaseAccessLevel)
	assert.Equal(t, []string{
		"/api/v4/groups/acme/member_roles?page=",
		"/api/v4/groups/acme/member_roles?page=2",
	}, paths)
}

func TestListInstanceMemberRolesReportsStatus(t *testing.T) {
	// Synthetic: a non-admin token asking for instance roles; no target showed this.
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v4/member_roles", r.URL.Path)
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message": "403 Forbidden"}`)
	}))

	roles, err := listInstanceMemberRoles(client)
	assert.Nil(t, roles)
	require.Error(t, err)
	assert.True(t, isGitlabStatus(err, 403))
	assert.False(t, isGitlabStatus(err, 404))
}

func TestIsGitlabStatusIgnoresTransportErrors(t *testing.T) {
	// Synthetic: an error that never reached GitLab.
	assert.False(t, isGitlabStatus(errors.New("dial tcp: connection refused"), 403, 404))
	assert.False(t, isGitlabStatus(nil, 403))
}

func TestGetGroupDetailReadsRequireShaForMerge(t *testing.T) {
	// Synthetic: a GitLab 19.5+ group with the SHA requirement on and locked
	// for descendants; no target showed this.
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v4/groups/42", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id": 42, "require_sha_for_merge": true, "lock_require_sha_for_merge": true}`)
	}))

	grp, err := getGroupDetail(client, 42)
	require.NoError(t, err)
	args := map[string]*llx.RawData{}
	populateGroupDetailArgs(args, grp)
	assert.Equal(t, true, args["requireShaForMerge"].Value)
	assert.Equal(t, true, args["lockRequireShaForMerge"].Value)
}

func TestGetGroupDetailWithoutRequireShaForMerge(t *testing.T) {
	// Synthetic: a GitLab version before 19.5, whose group payload has no
	// require_sha_for_merge keys; no target showed this.
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id": 42, "membership_lock": true}`)
	}))

	grp, err := getGroupDetail(client, 42)
	require.NoError(t, err)
	args := map[string]*llx.RawData{}
	populateGroupDetailArgs(args, grp)
	assert.Equal(t, false, args["requireShaForMerge"].Value)
	assert.Equal(t, false, args["lockRequireShaForMerge"].Value)
}

func TestGetGroupDetailRefusalIsForbidden(t *testing.T) {
	// Synthetic: a token without read access to the group; no target showed this.
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message": "403 Forbidden"}`)
	}))
	grp, err := getGroupDetail(client, 42)
	assert.Nil(t, grp)
	assert.True(t, errors.Is(err, llx.ErrForbidden))

	// Synthetic: a group that no longer exists is not a refusal.
	notFound, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message": "404 Group Not Found"}`)
	}))
	_, err = getGroupDetail(notFound, 42)
	require.Error(t, err)
	assert.False(t, errors.Is(err, llx.ErrForbidden))
}
