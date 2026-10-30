// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox/team"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/dropbox/connection"
	"go.mondoo.com/mql/types"
)

// conn returns the Dropbox connection backing this runtime.
func (m *mqlDropboxMember) conn() *connection.DropboxConnection {
	return m.MqlRuntime.Connection.(*connection.DropboxConnection)
}

// id returns the team member ID as the resource's cache key. It is unique
// and stable across the team.
func (m *mqlDropboxMember) id() (string, error) {
	return "dropbox.member/" + m.TeamMemberId.Data, nil
}

// members lists every member enrolled in the team, fully paginating
// team/members/list_v2.
func (d *mqlDropbox) members() ([]any, error) {
	conn := d.conn()
	client := conn.Client()

	members, err := pagedFetch(
		func() ([]*team.TeamMemberInfoV2, string, bool, error) {
			resp, err := client.MembersListV2(&team.MembersListArg{Limit: 1000})
			if err != nil {
				return nil, "", false, err
			}
			return resp.Members, resp.Cursor, resp.HasMore, nil
		},
		func(cursor string) ([]*team.TeamMemberInfoV2, string, bool, error) {
			resp, err := client.MembersListContinueV2(&team.MembersListContinueArg{Cursor: cursor})
			if err != nil {
				return nil, "", false, err
			}
			return resp.Members, resp.Cursor, resp.HasMore, nil
		},
	)
	if err != nil {
		return nil, err
	}

	var all []any
	for _, m := range members {
		r, err := newMqlDropboxMember(d.MqlRuntime, m)
		if err != nil {
			return nil, err
		}
		all = append(all, r)
	}
	return all, nil
}

// newMqlDropboxMember maps a single SDK team member to its MQL resource.
func newMqlDropboxMember(runtime *plugin.Runtime, m *team.TeamMemberInfoV2) (plugin.Resource, error) {
	profile := m.Profile

	var status string
	if profile.Status != nil {
		status = profile.Status.Tag
	}

	var membershipType string
	if profile.MembershipType != nil {
		membershipType = profile.MembershipType.Tag
	}

	var displayName string
	if profile.Name != nil {
		displayName = profile.Name.DisplayName
	}

	roleNames := make([]string, 0, len(m.Roles))
	for _, role := range m.Roles {
		if role != nil && role.Name != "" {
			roleNames = append(roleNames, role.Name)
		}
	}

	secondaryEmails := make([]any, 0, len(profile.SecondaryEmails))
	for _, se := range profile.SecondaryEmails {
		if se != nil {
			secondaryEmails = append(secondaryEmails, se.Email)
		}
	}

	res, err := CreateResource(runtime, "dropbox.member", map[string]*llx.RawData{
		"__id":            llx.StringData("dropbox.member/" + profile.TeamMemberId),
		"teamMemberId":    llx.StringData(profile.TeamMemberId),
		"email":           llx.StringData(profile.Email),
		"emailVerified":   llx.BoolData(profile.EmailVerified),
		"displayName":     llx.StringData(displayName),
		"status":          llx.StringData(status),
		"membershipType":  llx.StringData(membershipType),
		"role":            llx.StringData(strings.Join(roleNames, ", ")),
		"secondaryEmails": llx.ArrayData(secondaryEmails, types.String),
		"joinedAt":        llx.TimeDataPtr(dbxTimePtr(profile.JoinedOn)),
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// devices resolves the devices linked to this member's account from the
// team-wide, member-grouped device cache on the connection.
func (m *mqlDropboxMember) devices() ([]any, error) {
	conn := m.conn()
	pages, err := conn.DevicesByMember()
	if err != nil {
		return nil, err
	}
	for _, page := range pages {
		if page.TeamMemberId == m.TeamMemberId.Data {
			return mqlDropboxDevicesForMember(m.MqlRuntime, page)
		}
	}
	return []any{}, nil
}

// linkedApps resolves the third-party apps this member has linked from the
// team-wide, member-grouped linked-app cache on the connection.
func (m *mqlDropboxMember) linkedApps() ([]any, error) {
	conn := m.conn()
	pages, err := conn.LinkedAppsByMember()
	if err != nil {
		return nil, err
	}
	for _, page := range pages {
		if page.TeamMemberId == m.TeamMemberId.Data {
			return mqlDropboxLinkedAppsForMember(m.MqlRuntime, page)
		}
	}
	return []any{}, nil
}
