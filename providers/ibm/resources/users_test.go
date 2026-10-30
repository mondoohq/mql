// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/platform-services-go-sdk/accountmanagementv4"
	"github.com/IBM/platform-services-go-sdk/resourcemanagerv2"
	"github.com/IBM/platform-services-go-sdk/usermanagementv1"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// jsonServer answers every request with the next of bodies under status and
// records the request URLs.
func jsonServer(t *testing.T, status int, bodies []string, urls *[]string) string {
	t.Helper()
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if urls != nil {
			*urls = append(*urls, r.URL.String())
		}
		require.Less(t, n, len(bodies), "more requests than answers")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(bodies[n]))
		n++
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func userManagement(t *testing.T, url string) *usermanagementv1.UserManagementV1 {
	t.Helper()
	svc, err := usermanagementv1.NewUserManagementV1(&usermanagementv1.UserManagementV1Options{URL: url, Authenticator: &core.NoAuthAuthenticator{}})
	require.NoError(t, err)
	return svc
}

func accountManagement(t *testing.T, url string) *accountmanagementv4.AccountManagementV4 {
	t.Helper()
	svc, err := accountmanagementv4.NewAccountManagementV4(&accountmanagementv4.AccountManagementV4Options{URL: url, Authenticator: &core.NoAuthAuthenticator{}})
	require.NoError(t, err)
	return svc
}

func TestListUsersFollowsNextURL(t *testing.T) {
	var urls []string
	url := jsonServer(t, http.StatusOK, []string{
		`{"total_results": 2, "limit": 1, "next_url": "/v2/accounts/acc/users?limit=1&_start=page2",
		  "resources": [{"iam_id": "IBMid-1", "user_id": "owner@example.com", "email": "owner@example.com",
		    "firstname": "Ada", "lastname": "Owner", "realm": "IBMid", "state": "ACTIVE", "added_on": "2026-01-02T03:04:05Z"}]}`,
		`{"total_results": 2, "limit": 1,
		  "resources": [{"iam_id": "IBMid-2", "user_id": "invited@example.com", "state": "PENDING"}]}`,
	}, &urls)

	users, err := listUsers(userManagement(t, url), "acc")
	require.NoError(t, err)
	require.Len(t, users, 2)
	assert.Equal(t, "IBMid-2", *users[1].IamID)
	require.Len(t, urls, 2)
	assert.NotContains(t, urls[0], "_start")
	assert.Contains(t, urls[1], "_start=page2", "the second request carries the first page's cursor")

	args := userArgs(users[0])
	assert.Equal(t, "ibm.iam.user/IBMid-1", args["__id"].Value)
	assert.Equal(t, "owner@example.com", args["userId"].Value)
	assert.Equal(t, "Ada", args["firstName"].Value)
	assert.Equal(t, "Owner", args["lastName"].Value)
	assert.Equal(t, "IBMid", args["realm"].Value)
	assert.Equal(t, "ACTIVE", args["state"].Value)
	assert.NotNil(t, args["addedOn"].Value)

	pending := userArgs(users[1])
	assert.Equal(t, "PENDING", pending["state"].Value)
	assert.Nil(t, pending["addedOn"].Value, "an absent timestamp is null")
}

func TestListUsersStuckCursor(t *testing.T) {
	page := `{"total_results": 2, "limit": 1, "next_url": "/v2/accounts/acc/users?_start=same", "resources": [{"iam_id": "IBMid-1"}]}`
	users, err := listUsers(userManagement(t, jsonServer(t, http.StatusOK, []string{page, page}, nil)), "acc")
	require.NoError(t, err)
	assert.Len(t, users, 2, "a cursor handed back unchanged ends the walk instead of looping")
}

func TestListUsersRefused(t *testing.T) {
	url := jsonServer(t, http.StatusForbidden, []string{`{"errors":[{"code":"x","message":"refused"}]}`}, nil)
	users, err := listUsers(userManagement(t, url), "acc")
	assert.Nil(t, users)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err), "a refusal is an error, not an empty list")
}

// The User Management and Resource Manager SDKs hide the HTTP problem of a
// failed call; withStatus restores the status from the response so a refusal
// is still classified as one.
func TestWithStatusOlderSDKs(t *testing.T) {
	refused := `{"errors":[{"code":"x","message":"refused"}]}`
	acc := "acc"

	um := userManagement(t, jsonServer(t, http.StatusForbidden, []string{refused}, nil))
	_, resp, err := um.ListUsers(&usermanagementv1.ListUsersOptions{AccountID: &acc})
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(classifyError(err, "")), "the SDK error alone hides the status")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(classifyError(withStatus(err, resp), "")))

	rm, err := resourcemanagerv2.NewResourceManagerV2(&resourcemanagerv2.ResourceManagerV2Options{
		URL: jsonServer(t, http.StatusForbidden, []string{refused}, nil), Authenticator: &core.NoAuthAuthenticator{},
	})
	require.NoError(t, err)
	_, resp, err = rm.ListResourceGroups(&resourcemanagerv2.ListResourceGroupsOptions{AccountID: &acc})
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(classifyError(withStatus(err, resp), "")))

	// An error that already carries its status, or a transport failure
	// without a response, is left alone.
	vpcErr := sdkError(t, http.StatusNotFound)
	assert.Same(t, vpcErr, withStatus(vpcErr, &core.DetailedResponse{StatusCode: http.StatusForbidden}))
	transport := errors.New("dial tcp: connection refused")
	assert.Same(t, transport, withStatus(transport, nil))
	assert.Nil(t, withStatus(nil, nil))
}

func TestAccountOwnerIamID(t *testing.T) {
	var urls []string
	url := jsonServer(t, http.StatusOK, []string{`{"name": "acct", "id": "acc", "owner": "owner@example.com",
		"owner_userid": "owner@example.com", "owner_iamid": "IBMid-1", "type": "PAYG", "status": "ACTIVE",
		"linked_softlayer_account": "", "team_directory_enabled": false, "traits": {"eu_supported": false, "poc": false, "hippa": false}}`}, &urls)
	owner, err := accountOwnerIamID(accountManagement(t, url), "acc")
	require.NoError(t, err)
	assert.Equal(t, "IBMid-1", owner)
	assert.Equal(t, []string{"/v4/accounts/acc"}, urls)

	assert.True(t, isAccountOwner("IBMid-1", owner))
	assert.False(t, isAccountOwner("IBMid-2", owner))
	assert.False(t, isAccountOwner("", ""), "an unknown owner matches nobody")

	refused := jsonServer(t, http.StatusForbidden, []string{`{"errors":[{"code":"x","message":"refused"}]}`}, nil)
	_, err = accountOwnerIamID(accountManagement(t, refused), "acc")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
}

func TestUserMfaOf(t *testing.T) {
	userMfa := map[string]any{"IBMid-1": "TOTP", "IBMid-3": ""}
	v, ok := userMfaOf(userMfa, "IBMid-1")
	assert.True(t, ok)
	assert.Equal(t, "TOTP", v)
	_, ok = userMfaOf(userMfa, "IBMid-2")
	assert.False(t, ok, "a user without an own setting has none")
	_, ok = userMfaOf(userMfa, "IBMid-3")
	assert.False(t, ok)
	_, ok = userMfaOf(userMfa, "")
	assert.False(t, ok)
}

func setValue[T any](v T) plugin.TValue[T] {
	return plugin.TValue[T]{Data: v, State: plugin.StateIsSet}
}

func TestPoliciesForIamID(t *testing.T) {
	direct := &mqlIbmIamPolicy{SubjectAttributes: setValue(map[string]any{"iam_id": "IBMid-1"})}
	other := &mqlIbmIamPolicy{SubjectAttributes: setValue(map[string]any{"iam_id": "IBMid-2"})}
	group := &mqlIbmIamPolicy{SubjectAttributes: setValue(map[string]any{"access_group_id": "AccessGroupId-1"})}
	list := []any{direct, other, group}

	assert.Equal(t, []any{direct}, policiesForIamID(list, "IBMid-1"))
	assert.Equal(t, []any{}, policiesForIamID(list, "IBMid-9"))
	assert.Equal(t, []any{}, policiesForIamID(list, ""))
}

func TestAccessGroupsWithMember(t *testing.T) {
	member := func(iamID string) any {
		return &mqlIbmIamAccessGroupMember{IamId: setValue(iamID)}
	}
	admins := &mqlIbmIamAccessGroup{Members: setValue([]any{member("IBMid-1"), member("iam-ServiceId-1")})}
	viewers := &mqlIbmIamAccessGroup{Members: setValue([]any{member("IBMid-2")})}
	empty := &mqlIbmIamAccessGroup{Members: setValue([]any{})}
	list := []any{admins, viewers, empty}

	got, err := accessGroupsWithMember(list, "IBMid-1")
	require.NoError(t, err)
	assert.Equal(t, []any{admins}, got)

	got, err = accessGroupsWithMember(list, "IBMid-3")
	require.NoError(t, err)
	assert.Equal(t, []any{}, got, "a user in no group")

	refused := &mqlIbmIamAccessGroup{Members: plugin.TValue[[]any]{
		Error: llx.Forbidden(errors.New("refused")),
		State: plugin.StateIsSet | plugin.StateIsNull,
	}}
	_, err = accessGroupsWithMember([]any{admins, refused}, "IBMid-1")
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err), "unreadable members are not \"not a member\"")
}

func TestAPIKeysOf(t *testing.T) {
	userKey := &mqlIbmIamApiKey{IamId: setValue("IBMid-1")}
	serviceKey := &mqlIbmIamApiKey{IamId: setValue("iam-ServiceId-1")}
	list := []any{userKey, serviceKey}

	assert.Equal(t, []any{userKey}, apiKeysOf(list, "IBMid-1"))
	assert.Equal(t, []any{serviceKey}, apiKeysOf(list, "iam-ServiceId-1"))
	assert.Equal(t, []any{}, apiKeysOf(list, ""))
}

func TestVolumeAttachmentTypes(t *testing.T) {
	attachment := func(id, typ string) string {
		return `{"id": "` + id + `", "name": "` + id + `", "href": "h", "type": "` + typ + `", "delete_volume_on_instance_delete": true,
			"instance": {"id": "i-1", "crn": "crn:i-1", "name": "web-1", "href": "h"}}`
	}
	boot := unmarshal[vpcv1.Volume](t, `{"id": "v-1", "volume_attachments": [`+attachment("a-1", "boot")+`]}`, vpcv1.UnmarshalVolume)
	assert.Equal(t, []string{"boot"}, volumeAttachmentTypes(*boot))

	data := unmarshal[vpcv1.Volume](t, `{"id": "v-2", "volume_attachments": [`+attachment("a-2", "data")+`]}`, vpcv1.UnmarshalVolume)
	assert.Equal(t, []string{"data"}, volumeAttachmentTypes(*data))

	unattached := unmarshal[vpcv1.Volume](t, `{"id": "v-3", "volume_attachments": []}`, vpcv1.UnmarshalVolume)
	assert.Equal(t, []string{}, volumeAttachmentTypes(*unattached))
}
