// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox/team"
	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox/team_common"
	"go.mondoo.com/mql/llx"
)

// id returns the group ID as the resource's cache key. It is unique and
// stable across the team.
func (g *mqlDropboxGroup) id() (string, error) {
	return "dropbox.group/" + g.GroupId.Data, nil
}

// groups lists every team-managed group, fully paginating team/groups/list.
func (d *mqlDropbox) groups() ([]any, error) {
	conn := d.conn()
	client := conn.Client()

	groups, err := pagedFetch(
		func() ([]*team_common.GroupSummary, string, bool, error) {
			resp, err := client.GroupsList(&team.GroupsListArg{Limit: 1000})
			if err != nil {
				return nil, "", false, err
			}
			return resp.Groups, resp.Cursor, resp.HasMore, nil
		},
		func(cursor string) ([]*team_common.GroupSummary, string, bool, error) {
			resp, err := client.GroupsListContinue(&team.GroupsListContinueArg{Cursor: cursor})
			if err != nil {
				return nil, "", false, err
			}
			return resp.Groups, resp.Cursor, resp.HasMore, nil
		},
	)
	if err != nil {
		return nil, err
	}

	var all []any
	for _, g := range groups {
		var managementType string
		if g.GroupManagementType != nil {
			managementType = g.GroupManagementType.Tag
		}

		r, err := CreateResource(d.MqlRuntime, "dropbox.group", map[string]*llx.RawData{
			"__id":           llx.StringData(g.GroupId),
			"groupId":        llx.StringData(g.GroupId),
			"name":           llx.StringData(g.GroupName),
			"externalId":     llx.StringData(g.GroupExternalId),
			"memberCount":    llx.IntData(int64(g.MemberCount)),
			"managementType": llx.StringData(managementType),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, r)
	}
	return all, nil
}
