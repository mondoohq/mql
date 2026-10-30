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

func TestSlackbotSkillArgs(t *testing.T) {
	// Synthetic: the first entry is the example response of the Slack API
	// reference for admin.slackbot.skills.list, the second an unedited skill
	// with date_updated null; no Enterprise Grid org was available.
	body := `{"ok":true,"skills":[
		{"id":"F0123ABCD","display_name":"Daily priorities",
		 "description":"Reviews information from Slack and your calendar to suggest priorities for the day.",
		 "category":"productivity","creator_id":"U0123ABCD","date_created":1790000000,"date_updated":1790100000,
		 "visibility":"invite_only","is_official":false,"usage_count":1840,"library_count":312,
		 "auto_enabled":{"permission_type":"named_entities","usergroup_ids":["S0123ABCD"]}},
		{"id":"F0456EFGH","display_name":"Release notes","category":"engineering","creator_id":"W0456EFGH",
		 "date_created":1790000000,"date_updated":null,"visibility":"invite_only","is_official":true,
		 "usage_count":0,"library_count":0,"auto_enabled":{"permission_type":"everyone","usergroup_ids":[]}}],
		"response_metadata":{"next_cursor":""}}`

	var resp slack.AdminSlackbotSkillsListResponse
	require.NoError(t, json.Unmarshal([]byte(body), &resp))
	require.Len(t, resp.Skills, 2)

	first := slackbotSkillArgs(resp.Skills[0])
	assert.Equal(t, "F0123ABCD", first["id"].Value)
	assert.Equal(t, "Daily priorities", first["displayName"].Value)
	assert.Equal(t, "productivity", first["category"].Value)
	assert.Equal(t, "invite_only", first["visibility"].Value)
	assert.Equal(t, false, first["isOfficial"].Value)
	assert.Equal(t, int64(1840), first["usageCount"].Value)
	assert.Equal(t, int64(312), first["libraryCount"].Value)
	assert.Equal(t, "named_entities", first["autoEnabledPermissionType"].Value)
	created, ok := first["created"].Value.(*time.Time)
	require.True(t, ok, "created should be a time")
	assert.True(t, created.Equal(time.Unix(1790000000, 0)))
	updated, ok := first["updated"].Value.(*time.Time)
	require.True(t, ok, "updated should be a time")
	assert.True(t, updated.Equal(time.Unix(1790100000, 0)))
	assert.Equal(t, "U0123ABCD", resp.Skills[0].CreatorID)
	assert.Equal(t, []string{"S0123ABCD"}, resp.Skills[0].AutoEnabled.UsergroupIDs)

	second := slackbotSkillArgs(resp.Skills[1])
	assert.Nil(t, second["updated"].Value, "a never-edited skill has no update date")
	assert.Equal(t, true, second["isOfficial"].Value)
	assert.Equal(t, "everyone", second["autoEnabledPermissionType"].Value)
}

func TestUnlistedUserGroupArgs(t *testing.T) {
	// Synthetic: a group ID the workspace's usergroups.list does not return.
	args := unlistedUserGroupArgs("S0FOREIGN")
	assert.Equal(t, "S0FOREIGN", args["id"].Value)
	for k, v := range args {
		if k == "id" {
			continue
		}
		assert.Nil(t, v.Value, "field %s should be null", k)
	}
	// every listing field is present, so none reads as "no data"
	assert.Len(t, args, len(userGroupArgs(slack.UserGroup{})))
}
