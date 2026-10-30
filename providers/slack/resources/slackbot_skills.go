// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/slack-go/slack"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	adminSkillsReadScope = "admin.skills:read"
	// admin.slackbot.skills.list accepts 1 to 200 items per page
	adminSkillsPageLimit = 200
)

type mqlSlackSlackbotSkillInternal struct {
	cacheCreatorID    string
	cacheUserGroupIDs []string
}

func (x *mqlSlackSlackbotSkill) id() (string, error) {
	return "slack.slackbotSkill/" + x.Id.Data, nil
}

func (s *mqlSlack) slackbotSkills() ([]any, error) {
	client, _, err := adminClient(s.MqlRuntime)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	res := []any{}
	err = walkCursor(func(cursor string) (string, error) {
		opts := []slack.AdminSlackbotSkillsListOption{
			slack.AdminSlackbotSkillsListOptionLimit(adminSkillsPageLimit),
		}
		if cursor != "" {
			opts = append(opts, slack.AdminSlackbotSkillsListOptionCursor(cursor))
		}
		resp, err := client.AdminSlackbotSkillsListContext(ctx, opts...)
		if err != nil {
			return "", classifyError(err, adminSkillsReadScope)
		}
		for i := range resp.Skills {
			r, err := newMqlSlackSlackbotSkill(s.MqlRuntime, resp.Skills[i])
			if err != nil {
				return "", err
			}
			res = append(res, r)
		}
		return resp.ResponseMetadata.Cursor, nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// slackbotSkillArgs maps one admin.slackbot.skills.list entry onto
// slack.slackbotSkill.
func slackbotSkillArgs(skill slack.AdminSlackbotSkill) map[string]*llx.RawData {
	updated := llx.NilData
	if skill.DateUpdated != nil {
		updated = unixTimeData(*skill.DateUpdated)
	}
	return map[string]*llx.RawData{
		"id":                        llx.StringData(skill.ID),
		"displayName":               llx.StringData(skill.DisplayName),
		"description":               llx.StringData(skill.Description),
		"category":                  llx.StringData(skill.Category),
		"created":                   unixTimeData(skill.DateCreated),
		"updated":                   updated,
		"visibility":                llx.StringData(skill.Visibility),
		"isOfficial":                llx.BoolData(skill.IsOfficial),
		"usageCount":                llx.IntData(int64(skill.UsageCount)),
		"libraryCount":              llx.IntData(int64(skill.LibraryCount)),
		"autoEnabledPermissionType": llx.StringData(skill.AutoEnabled.PermissionType),
	}
}

func newMqlSlackSlackbotSkill(runtime *plugin.Runtime, skill slack.AdminSlackbotSkill) (*mqlSlackSlackbotSkill, error) {
	r, err := CreateResource(runtime, "slack.slackbotSkill", slackbotSkillArgs(skill))
	if err != nil {
		return nil, err
	}
	res := r.(*mqlSlackSlackbotSkill)
	res.cacheCreatorID = skill.CreatorID
	res.cacheUserGroupIDs = skill.AutoEnabled.UsergroupIDs
	return res, nil
}

func (x *mqlSlackSlackbotSkill) createdBy() (*mqlSlackUser, error) {
	return slackUserRef(x.MqlRuntime, x.cacheCreatorID, &x.CreatedBy)
}

// autoEnabledUserGroups resolves the skill's user group IDs against the
// workspace's user group listing. A group the workspace cannot list (a group
// owned by another workspace of the organization) is still returned, carrying
// only its ID, so the list never reads shorter than what Slack reported.
func (x *mqlSlackSlackbotSkill) autoEnabledUserGroups() ([]any, error) {
	if len(x.cacheUserGroupIDs) == 0 {
		return []any{}, nil
	}

	r, err := CreateResource(x.MqlRuntime, "slack", nil)
	if err != nil {
		return nil, err
	}
	groups := r.(*mqlSlack).GetUserGroups()
	if groups.Error != nil {
		return nil, groups.Error
	}
	byID := map[string]any{}
	for _, g := range groups.Data {
		group, ok := g.(*mqlSlackUserGroup)
		if !ok {
			return nil, errors.New("unexpected type in slack user group list")
		}
		byID[group.Id.Data] = group
	}

	res := make([]any, 0, len(x.cacheUserGroupIDs))
	for _, id := range x.cacheUserGroupIDs {
		if g, ok := byID[id]; ok {
			res = append(res, g)
			continue
		}
		g, err := CreateResource(x.MqlRuntime, "slack.userGroup", unlistedUserGroupArgs(id))
		if err != nil {
			return nil, err
		}
		res = append(res, g)
	}
	return res, nil
}

// unlistedUserGroupArgs builds a slack.userGroup that carries only its ID,
// with every listing field null, for a group the workspace cannot list.
func unlistedUserGroupArgs(id string) map[string]*llx.RawData {
	args := userGroupArgs(slack.UserGroup{})
	for k := range args {
		args[k] = llx.NilData
	}
	args["id"] = llx.StringData(id)
	return args
}
