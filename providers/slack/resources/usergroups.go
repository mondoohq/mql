// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/slack-go/slack"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/slack/connection"
)

func (s *mqlSlack) userGroups() ([]any, error) {
	conn := s.MqlRuntime.Connection.(*connection.SlackConnection)
	client := conn.Client()
	if client == nil {
		return nil, errors.New("cannot retrieve new data while using a mock connection")
	}

	// requires usergroups:read scope
	ctx := context.Background()
	groups, err := client.GetUserGroupsContext(ctx,
		slack.GetUserGroupsOptionIncludeCount(true),
		slack.GetUserGroupsOptionIncludeDisabled(true),
	)
	if err != nil {
		return nil, err
	}
	var list []any
	for i := range groups {
		mqlGroup, err := newMqlSlackUserGroup(s.MqlRuntime, groups[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlGroup)
	}

	return list, nil
}

// mqlSlackUserGroupInternal caches the user IDs backing the lifecycle
// createdBy()/updatedBy()/deletedBy() typed references. These IDs are often
// empty (deletedBy is empty for every group that has not been deleted), so
// they are resolved lazily and guarded rather than looked up eagerly.
type mqlSlackUserGroupInternal struct {
	cacheCreatedBy string
	cacheUpdatedBy string
	cacheDeletedBy string
}

// userGroupArgs maps a usergroups.list entry onto the slack.userGroup fields
// that come straight from the listing.
func userGroupArgs(userGroup slack.UserGroup) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":                  llx.StringData(userGroup.ID),
		"teamId":              llx.StringData(userGroup.TeamID),
		"name":                llx.StringData(userGroup.Name),
		"description":         llx.StringData(userGroup.Description),
		"handle":              llx.StringData(userGroup.Handle),
		"isExternal":          llx.BoolData(userGroup.IsExternal),
		"isIdpGroup":          llx.BoolData(userGroup.IsIDPGroup),
		"autoProvision":       llx.BoolData(userGroup.AutoProvision),
		"isMembershipLocked":  llx.BoolData(userGroup.IsMembershipLocked),
		"isEditingRestricted": llx.BoolData(userGroup.IsEditingRestricted),
		"isOrgLevel":          llx.BoolData(userGroup.IsOrgLevel),
		"created":             llx.TimeData(userGroup.DateCreate.Time()),
		"updated":             llx.TimeData(userGroup.DateUpdate.Time()),
		"deleted":             llx.TimeData(userGroup.DateDelete.Time()),
		"userCount":           llx.IntData(int64(userGroup.UserCount)),
	}
}

func newMqlSlackUserGroup(runtime *plugin.Runtime, userGroup slack.UserGroup) (any, error) {
	r, err := CreateResource(runtime, "slack.userGroup", userGroupArgs(userGroup))
	if err != nil {
		return nil, err
	}

	mqlGroup := r.(*mqlSlackUserGroup)
	mqlGroup.cacheCreatedBy = userGroup.CreatedBy
	mqlGroup.cacheUpdatedBy = userGroup.UpdatedBy
	mqlGroup.cacheDeletedBy = userGroup.DeletedBy
	return mqlGroup, nil
}

func (x *mqlSlackUserGroup) id() (string, error) {
	return "slack.userGroup/" + x.Id.Data, nil
}

// userRef resolves a slack.user reference for the given ID, or returns a null
// reference when the ID is empty. deletedBy is empty for every group that has
// not been deleted, and createdBy/updatedBy can be empty for auto-provisioned
// groups; resolving an empty ID would fail the whole userGroups listing.
func (s *mqlSlackUserGroup) userRef(id string, field *plugin.TValue[*mqlSlackUser]) (*mqlSlackUser, error) {
	if id == "" {
		*field = plugin.TValue[*mqlSlackUser]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}
	r, err := NewResource(s.MqlRuntime, "slack.user", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlSlackUser), nil
}

func (s *mqlSlackUserGroup) createdBy() (*mqlSlackUser, error) {
	return s.userRef(s.cacheCreatedBy, &s.CreatedBy)
}

func (s *mqlSlackUserGroup) updatedBy() (*mqlSlackUser, error) {
	return s.userRef(s.cacheUpdatedBy, &s.UpdatedBy)
}

func (s *mqlSlackUserGroup) deletedBy() (*mqlSlackUser, error) {
	return s.userRef(s.cacheDeletedBy, &s.DeletedBy)
}

func (s *mqlSlackUserGroup) members() ([]any, error) {
	conn := s.MqlRuntime.Connection.(*connection.SlackConnection)
	client := conn.Client()
	if client == nil {
		return nil, errors.New("cannot retrieve new data while using a mock connection")
	}

	userID := s.Id.Data

	var list []any

	members, err := client.GetUserGroupMembers(userID)
	if err != nil {
		return nil, err
	}

	for i := range members {
		user, err := NewResource(s.MqlRuntime, "slack.user", map[string]*llx.RawData{
			"id": llx.StringData(members[i]),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, user)
	}

	return list, nil
}
