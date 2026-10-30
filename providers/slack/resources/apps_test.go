// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppResolutionArgs(t *testing.T) {
	// Synthetic: shaped after the example response of the Slack API reference
	// for admin.apps.approved.list; no Enterprise Grid org was available.
	body := `{"ok":true,"approved_apps":[{
		"app":{"id":"A0EXAMPLE1","name":"Example App","description":"Short app description",
			"help_url":"https://example.com/help","privacy_policy_url":"https://example.com/privacy",
			"app_homepage_url":"https://example.com","app_directory_url":"https://slack.com/apps/A0EXAMPLE1",
			"is_app_directory_approved":true,"is_granular_bot_app":true,"is_internal":false,
			"developer_type":"third_party","socket_mode_enabled":true,"additional_info":"info"},
		"scopes":[
			{"name":"chat:write","description":"Send messages","is_sensitive":false,"token_type":"bot"},
			{"name":"channels:history","description":"View messages","is_sensitive":true,"token_type":"user"}],
		"date_updated":1700000000,
		"last_resolved_by":{"actor_id":"W0EXAMPLE1","actor_type":"user"}}],
		"response_metadata":{"next_cursor":"dXNlcjpVMEc5V0ZYTlo="}}`

	var resp slack.AdminAppsApprovedListResponse
	require.NoError(t, json.Unmarshal([]byte(body), &resp))
	require.Len(t, resp.ApprovedApps, 1)
	assert.Equal(t, "dXNlcjpVMEc5V0ZYTlo=", resp.ResponseMetadata.Cursor)
	item := resp.ApprovedApps[0]

	app := appArgs(item.App)
	assert.Equal(t, "A0EXAMPLE1", app["id"].Value)
	assert.Equal(t, "Example App", app["name"].Value)
	assert.Equal(t, "https://example.com/help", app["helpUrl"].Value)
	assert.Equal(t, "https://example.com/privacy", app["privacyPolicyUrl"].Value)
	assert.Equal(t, "https://example.com", app["homepageUrl"].Value)
	assert.Equal(t, "https://slack.com/apps/A0EXAMPLE1", app["appDirectoryUrl"].Value)
	assert.Equal(t, true, app["isAppDirectoryApproved"].Value)
	assert.Equal(t, true, app["isGranularBotApp"].Value)
	assert.Equal(t, false, app["isInternal"].Value)
	assert.Equal(t, "third_party", app["developerType"].Value)
	assert.Equal(t, true, app["socketModeEnabled"].Value)
	assert.Equal(t, "info", app["additionalInfo"].Value)

	args := appResolutionArgs(appStatusApproved, item)
	assert.Equal(t, "approved", args["status"].Value)
	assert.Equal(t, []any{"chat:write", "channels:history"}, args["scopes"].Value)
	assert.Equal(t, []any{"channels:history"}, args["sensitiveScopes"].Value)
	assert.Equal(t, "user", args["lastResolvedByType"].Value)
	updated, ok := args["updated"].Value.(*time.Time)
	require.True(t, ok, "updated should be a time")
	assert.True(t, updated.Equal(time.Unix(1700000000, 0)))
	assert.Equal(t, "W0EXAMPLE1", resolvedByUserID(item.LastResolvedBy))
}

func TestAppResolutionArgsAbsentValues(t *testing.T) {
	// Synthetic: an entry without scopes, update date or resolving actor.
	var item slack.AdminAppListItem
	require.NoError(t, json.Unmarshal([]byte(`{"app":{"id":"A1"}}`), &item))

	args := appResolutionArgs(appStatusRestricted, item)
	assert.Equal(t, "restricted", args["status"].Value)
	assert.Equal(t, []any{}, args["scopes"].Value)
	assert.Equal(t, []any{}, args["sensitiveScopes"].Value)
	assert.Nil(t, args["updated"].Value)
	assert.Equal(t, "", resolvedByUserID(item.LastResolvedBy))
}

func TestResolvedByUserID(t *testing.T) {
	// Synthetic: the reference documents only actor_type "user".
	assert.Equal(t, "W1", resolvedByUserID(slack.AdminAppResolutionActor{ActorID: "W1", ActorType: "user"}))
	assert.Equal(t, "W1", resolvedByUserID(slack.AdminAppResolutionActor{ActorID: "W1"}))
	assert.Equal(t, "", resolvedByUserID(slack.AdminAppResolutionActor{ActorID: "A1", ActorType: "app"}))
}

func TestAppRequestArgs(t *testing.T) {
	// Synthetic: shaped after the example response of the Slack API reference
	// for admin.apps.requests.list; no Enterprise Grid org was available.
	body := `{"ok":true,"app_requests":[
		{"id":"Ar0EXAMPLE1","app":{"id":"A0EXAMPLE","name":"Example App","is_internal":true,"developer_type":"internal"},
		 "previous_resolution":null,
		 "user":{"id":"W0EXAMPLE","name":"Example User","email":"user@example.com"},
		 "team":{"id":"T0EXAMPLE","name":"Example Corp","domain":"examplecorp"},
		 "scopes":[{"name":"incoming-webhook","token_type":"user","is_sensitive":false,"is_optional":true,"is_approved":false},
		           {"name":"files:read","token_type":"user","is_sensitive":true}],
		 "message":"Example request message.","is_user_app_collaborator":true,"date_created":1700000000},
		{"id":"Ar0EXAMPLE2","app":{"id":"A0OTHER"},
		 "previous_resolution":{"status":"restricted","scopes":[]},
		 "user":{"id":"W0OTHER"},"scopes":[],"message":"","is_user_app_collaborator":false}],
		"response_metadata":{"next_cursor":""}}`

	var resp slack.AdminAppsRequestsListResponse
	require.NoError(t, json.Unmarshal([]byte(body), &resp))
	require.Len(t, resp.AppRequests, 2)

	first := appRequestArgs(resp.AppRequests[0])
	assert.Equal(t, "Ar0EXAMPLE1", first["id"].Value)
	assert.Equal(t, "Example request message.", first["message"].Value)
	assert.Equal(t, []any{"incoming-webhook", "files:read"}, first["scopes"].Value)
	assert.Equal(t, []any{"files:read"}, first["sensitiveScopes"].Value)
	assert.Equal(t, true, first["isUserAppCollaborator"].Value)
	assert.Nil(t, first["previousResolutionStatus"].Value, "no earlier decision reads as null")
	created, ok := first["created"].Value.(*time.Time)
	require.True(t, ok, "created should be a time")
	assert.True(t, created.Equal(time.Unix(1700000000, 0)))
	assert.Equal(t, "W0EXAMPLE", resp.AppRequests[0].User.ID)

	second := appRequestArgs(resp.AppRequests[1])
	assert.Equal(t, "restricted", second["previousResolutionStatus"].Value)
	assert.Equal(t, false, second["isUserAppCollaborator"].Value)
	assert.Nil(t, second["created"].Value, "absent date_created reads as null")
}

func TestAppResolutionIDsDifferByStatus(t *testing.T) {
	// Synthetic: the same app listed as approved and as restricted must not
	// share a cache entry.
	app := &mqlSlackApp{Id: strVal("A1")}
	approved := &mqlSlackAppResolution{Status: strVal("approved")}
	approved.App.Data = app
	restricted := &mqlSlackAppResolution{Status: strVal("restricted")}
	restricted.App.Data = app

	a, _ := approved.id()
	r, _ := restricted.id()
	assert.Equal(t, "slack.appResolution/approved/A1", a)
	assert.NotEqual(t, a, r)
}
