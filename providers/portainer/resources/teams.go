// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"github.com/portainer/client-api-go/v2/pkg/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/portainer/connection"
)

func newMqlPortainerTeam(runtime *plugin.Runtime, id int64, name string) (*mqlPortainerTeam, error) {
	res, err := CreateResource(runtime, "portainer.team", map[string]*llx.RawData{
		"__id": llx.StringData("portainer.team/" + strconv.FormatInt(id, 10)),
		"id":   llx.IntData(id),
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlPortainerTeam), nil
}

func (r *mqlPortainer) teams() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	teams, err := conn.Teams()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(teams))
	for _, t := range teams {
		mqlTeam, err := newMqlPortainerTeam(r.MqlRuntime, t.ID, t.Name)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTeam)
	}
	return res, nil
}

// teamMembers resolves the memberships of one team to the matching users.
// Memberships pointing at a user that is not in the list are skipped: the users
// endpoint hides administrator accounts from non-administrator tokens, and
// orphaned memberships outlive a deleted user.
func teamMembers(memberships []*models.PortainerTeamMembership, users []*models.PortainereeUser, teamID int64) []*models.PortainereeUser {
	userByID := make(map[int64]*models.PortainereeUser, len(users))
	for _, u := range users {
		userByID[u.ID] = u
	}

	res := []*models.PortainereeUser{}
	for _, m := range memberships {
		if m.TeamID != teamID {
			continue
		}
		if u, ok := userByID[m.UserID]; ok {
			res = append(res, u)
		}
	}
	return res
}

// teamMemberRoles maps one team's memberships to a username-keyed dict of
// membership role names, skipping members that cannot be resolved to a user.
func teamMemberRoles(memberships []*models.PortainerTeamMembership, users []*models.PortainereeUser, teamID int64) map[string]any {
	userByID := make(map[int64]*models.PortainereeUser, len(users))
	for _, u := range users {
		userByID[u.ID] = u
	}

	res := map[string]any{}
	for _, m := range memberships {
		if m.TeamID != teamID {
			continue
		}
		u, ok := userByID[m.UserID]
		if !ok {
			continue
		}
		res[u.Username] = connection.MembershipRole(m.Role)
	}
	return res
}

// members returns the users that belong to the team, resolved through the
// instance team memberships.
func (r *mqlPortainerTeam) members() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	memberships, err := conn.TeamMemberships()
	if err != nil {
		return nil, err
	}
	users, err := conn.Users()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, u := range teamMembers(memberships, users, r.Id.Data) {
		mqlUser, err := newMqlPortainerUser(r.MqlRuntime, u)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlUser)
	}
	return res, nil
}

// memberRoles reports each member's role within the team, keyed by username.
func (r *mqlPortainerTeam) memberRoles() (any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	memberships, err := conn.TeamMemberships()
	if err != nil {
		return nil, err
	}
	users, err := conn.Users()
	if err != nil {
		return nil, err
	}
	return teamMemberRoles(memberships, users, r.Id.Data), nil
}
