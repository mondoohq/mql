// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gitlab/connection"

	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
)

// This file models membership that is not yet, or not only, a member list:
// invitations nobody has accepted, and the paid seats of a top-level group.
// Invitation ids are unique per instance but the same invitation is listed
// only under its own group or project, so both scopes key on the owner as
// well. Billable member ids are user ids, which repeat in every group.

//
// Pending invitations
//

// pendingInvitations lists the invitations to the group nobody has accepted.
func (g *mqlGitlabGroup) pendingInvitations() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)
	groupID := g.Id.Data

	all, err := collectPages(func(page int64) ([]*gitlab.PendingInvite, *gitlab.Response, error) {
		return conn.Client().Invites.ListPendingGroupInvitations(groupID, &gitlab.ListPendingInvitationsOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
	})
	if err != nil {
		if err = gatedError(err); err != nil {
			return nil, err
		}
		return []any{}, nil
	}
	return newPendingInvitations(g.MqlRuntime, all, func(id int64) string {
		return groupScopedID("gitlab.pendingInvitation/group", groupID, strconv.FormatInt(id, 10))
	})
}

// pendingInvitations lists the invitations to the project nobody has accepted.
func (p *mqlGitlabProject) pendingInvitations() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := p.Id.Data

	all, err := collectPages(func(page int64) ([]*gitlab.PendingInvite, *gitlab.Response, error) {
		return conn.Client().Invites.ListPendingProjectInvitations(projectID, &gitlab.ListPendingInvitationsOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
	})
	if err != nil {
		if err = gatedError(err); err != nil {
			return nil, err
		}
		return []any{}, nil
	}
	return newPendingInvitations(p.MqlRuntime, all, func(id int64) string {
		return projectScopedID("gitlab.pendingInvitation/project", projectID, strconv.FormatInt(id, 10))
	})
}

func newPendingInvitations(runtime *plugin.Runtime, invites []*gitlab.PendingInvite, key func(int64) string) ([]any, error) {
	res := make([]any, 0, len(invites))
	for _, invite := range invites {
		if invite == nil {
			continue
		}
		mqlInvite, err := CreateResource(runtime, "gitlab.pendingInvitation", map[string]*llx.RawData{
			"__id":          llx.StringData(key(invite.ID)),
			"id":            llx.IntData(invite.ID),
			"inviteEmail":   llx.StringData(invite.InviteEmail),
			"userName":      llx.StringData(invite.UserName),
			"accessLevel":   llx.IntData(int64(invite.AccessLevel)),
			"createdAt":     llx.TimeDataPtr(invite.CreatedAt),
			"expiresAt":     llx.TimeDataPtr(invite.ExpiresAt),
			"createdByName": llx.StringData(invite.CreatedByName),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInvite)
	}
	return res, nil
}

//
// Billable members
//

// isSubgroupPath reports whether a group full path names a subgroup. Only a
// top-level group has a path without a separator.
func isSubgroupPath(fullPath string) bool {
	return strings.Contains(strings.Trim(fullPath, "/"), "/")
}

// billableMembers lists the members taking up a paid seat. GitLab counts seats
// on top-level groups only, so a subgroup reads as null without a request.
// The endpoint is for owners of the group; other roles are refused.
func (g *mqlGitlabGroup) billableMembers() ([]any, error) {
	if isSubgroupPath(g.FullPath.Data) {
		g.BillableMembers.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)
	groupID := g.Id.Data

	all, err := collectPages(func(page int64) ([]*gitlab.BillableGroupMember, *gitlab.Response, error) {
		return conn.Client().Groups.ListBillableGroupMembers(groupID, &gitlab.ListBillableGroupMembersOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
	})
	if err != nil {
		if err = gatedError(err); err != nil {
			return nil, err
		}
		return []any{}, nil
	}

	res := make([]any, 0, len(all))
	for _, m := range all {
		if m == nil {
			continue
		}
		member, err := CreateResource(g.MqlRuntime, "gitlab.group.billableMember", map[string]*llx.RawData{
			"__id":           llx.StringData(groupScopedID("gitlab.group.billableMember", groupID, strconv.FormatInt(m.ID, 10))),
			"id":             llx.IntData(m.ID),
			"username":       llx.StringData(m.Username),
			"name":           llx.StringData(m.Name),
			"state":          llx.StringData(m.State),
			"membershipType": llx.StringData(m.MembershipType),
			"isLastOwner":    llx.BoolData(m.IsLastOwner),
			"removable":      llx.BoolData(m.Removable),
			"createdAt":      llx.TimeDataPtr(m.CreatedAt),
			"lastLoginAt":    llx.TimeDataPtr(m.LastLoginAt),
			"lastActivityOn": llx.TimeDataPtr(isoTimePtr(m.LastActivityOn)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, member)
	}
	return res, nil
}

func (m *mqlGitlabGroupBillableMember) user() (*mqlGitlabUser, error) {
	if m.Id.Data <= 0 {
		m.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return gitlabUserRef(m.MqlRuntime, m.Id.Data)
}
