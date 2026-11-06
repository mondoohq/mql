// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gitlab/connection"
	"go.mondoo.com/mql/utils/syncx"
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

// newTestGroupRuntime returns a runtime whose GitLab connection talks to
// handler.
func newTestGroupRuntime(t *testing.T, handler http.Handler) *plugin.Runtime {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	conn, err := connection.NewGitLabConnection(1, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{"token": "test-token", "url": server.URL},
	})
	require.NoError(t, err)
	return &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
}

func TestSubgroupsResolveDetailOnlyFields(t *testing.T) {
	// Synthetic: GET /groups/:id/subgroups returns Entities::Group, which has
	// none of the GroupDetail keys; GET /groups/:id carries them. No target
	// showed these values.
	var detailCalls atomic.Int32
	runtime := newTestGroupRuntime(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/groups/1/subgroups":
			fmt.Fprint(w, `[{"id": 7, "name": "api", "path": "api", "full_path": "acme/api"}]`)
		case "/api/v4/groups/7":
			detailCalls.Add(1)
			fmt.Fprint(w, `{
				"id": 7, "name": "api", "path": "api", "full_path": "acme/api",
				"membership_lock": true,
				"prevent_forking_outside_group": true,
				"ip_restriction_ranges": "10.0.0.0/8,192.168.0.0/16",
				"allowed_email_domains_list": "example.com",
				"shared_with_groups": [{"group_id": 9, "group_name": "ops", "group_full_path": "ops", "group_access_level": 30}],
				"require_sha_for_merge": true,
				"lock_require_sha_for_merge": true
			}`)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	parent, err := CreateResource(runtime, "gitlab.group", map[string]*llx.RawData{"id": llx.IntData(1), "name": llx.StringData("acme"), "path": llx.StringData("acme")})
	require.NoError(t, err)
	subs := parent.(*mqlGitlabGroup).GetSubgroups()
	require.NoError(t, subs.Error)
	require.Len(t, subs.Data, 1)
	sub := subs.Data[0].(*mqlGitlabGroup)

	membershipLock := sub.GetMembershipLock()
	require.NoError(t, membershipLock.Error)
	assert.True(t, membershipLock.Data)
	preventForking := sub.GetPreventForkingOutsideGroup()
	require.NoError(t, preventForking.Error)
	assert.True(t, preventForking.Data)
	ipRanges := sub.GetIpRestrictionRanges()
	require.NoError(t, ipRanges.Error)
	assert.Equal(t, "10.0.0.0/8,192.168.0.0/16", ipRanges.Data)
	emailDomains := sub.GetAllowedEmailDomainsList()
	require.NoError(t, emailDomains.Error)
	assert.Equal(t, "example.com", emailDomains.Data)
	shared := sub.GetSharedWithGroups()
	require.NoError(t, shared.Error)
	assert.Equal(t, []any{map[string]any{
		"groupId":          int64(9),
		"groupName":        "ops",
		"groupFullPath":    "ops",
		"groupAccessLevel": int64(30),
	}}, shared.Data)
	assert.True(t, sub.GetRequireShaForMerge().Data)
	assert.True(t, sub.GetLockRequireShaForMerge().Data)

	assert.EqualValues(t, 1, detailCalls.Load(), "every detail-only field shares one GET /groups/:id")
}

func TestSubgroupDetailFieldRefusalIsForbidden(t *testing.T) {
	// Synthetic: the token can list subgroups but GET on the subgroup is
	// refused; no target showed this.
	runtime := newTestGroupRuntime(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v4/groups/1/subgroups" {
			fmt.Fprint(w, `[{"id": 7, "name": "api", "path": "api"}]`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message": "403 Forbidden"}`)
	}))

	parent, err := CreateResource(runtime, "gitlab.group", map[string]*llx.RawData{"id": llx.IntData(1), "name": llx.StringData("acme"), "path": llx.StringData("acme")})
	require.NoError(t, err)
	subs := parent.(*mqlGitlabGroup).GetSubgroups()
	require.NoError(t, subs.Error)
	require.Len(t, subs.Data, 1)
	sub := subs.Data[0].(*mqlGitlabGroup)

	assert.True(t, errors.Is(sub.GetMembershipLock().Error, llx.ErrForbidden))
	assert.True(t, errors.Is(sub.GetSharedWithGroups().Error, llx.ErrForbidden))
}

func TestPopulateGroupDetailArgsSetsDetailOnlyFields(t *testing.T) {
	// Synthetic: a group read from GET /groups/:id gets the detail-only
	// fields set at init, so no second GET is needed.
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id": 42, "membership_lock": true, "prevent_forking_outside_group": true,
			"ip_restriction_ranges": "10.0.0.0/8", "allowed_email_domains_list": "example.com",
			"shared_with_groups": [{"group_id": 9, "group_access_level": 30}]}`)
	}))
	grp, err := getGroupDetail(client, 42)
	require.NoError(t, err)
	args := map[string]*llx.RawData{}
	populateGroupDetailArgs(args, grp)
	assert.Equal(t, true, args["membershipLock"].Value)
	assert.Equal(t, true, args["preventForkingOutsideGroup"].Value)
	assert.Equal(t, "10.0.0.0/8", args["ipRestrictionRanges"].Value)
	assert.Equal(t, "example.com", args["allowedEmailDomainsList"].Value)
	require.Len(t, args["sharedWithGroups"].Value, 1)

	listArgs := map[string]*llx.RawData{}
	populateGroupArgs(listArgs, grp)
	for _, k := range []string{"membershipLock", "preventForkingOutsideGroup", "ipRestrictionRanges", "allowedEmailDomainsList", "sharedWithGroups"} {
		assert.NotContains(t, listArgs, k, "list-shaped args must leave %s to groupDetail", k)
	}
}
