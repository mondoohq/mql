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

type mqlPortainerTeamMembershipInternal struct {
	cacheTeamId int64
	cacheUserId int64
}

func newMqlPortainerTeamMembership(runtime *plugin.Runtime, m *models.PortainerTeamMembership) (*mqlPortainerTeamMembership, error) {
	res, err := CreateResource(runtime, "portainer.teamMembership", map[string]*llx.RawData{
		"__id": llx.StringData("portainer.teamMembership/" + strconv.FormatInt(m.ID, 10)),
		"id":   llx.IntData(m.ID),
		"role": llx.StringData(connection.MembershipRole(m.Role)),
	})
	if err != nil {
		return nil, err
	}
	mqlMembership := res.(*mqlPortainerTeamMembership)
	mqlMembership.cacheTeamId = m.TeamID
	mqlMembership.cacheUserId = m.UserID
	return mqlMembership, nil
}

// newMqlPortainerTeamMemberships maps the memberships matching a filter to
// resources. A nil filter keeps every membership.
func newMqlPortainerTeamMemberships(runtime *plugin.Runtime, memberships []*models.PortainerTeamMembership, keep func(*models.PortainerTeamMembership) bool) ([]any, error) {
	res := []any{}
	for _, m := range memberships {
		if keep != nil && !keep(m) {
			continue
		}
		mqlMembership, err := newMqlPortainerTeamMembership(runtime, m)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlMembership)
	}
	return res, nil
}

func (r *mqlPortainer) teamMemberships() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	memberships, err := conn.TeamMemberships()
	if err != nil {
		return nil, err
	}
	return newMqlPortainerTeamMemberships(r.MqlRuntime, memberships, nil)
}

// memberships returns the memberships that make up the team roster.
func (r *mqlPortainerTeam) memberships() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	memberships, err := conn.TeamMemberships()
	if err != nil {
		return nil, err
	}
	teamID := r.Id.Data
	return newMqlPortainerTeamMemberships(r.MqlRuntime, memberships, func(m *models.PortainerTeamMembership) bool {
		return m.TeamID == teamID
	})
}

// memberships returns the team memberships held by the user.
func (r *mqlPortainerUser) memberships() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	memberships, err := conn.TeamMemberships()
	if err != nil {
		return nil, err
	}
	userID := r.Id.Data
	return newMqlPortainerTeamMemberships(r.MqlRuntime, memberships, func(m *models.PortainerTeamMembership) bool {
		return m.UserID == userID
	})
}

// team resolves the team the membership is in.
func (r *mqlPortainerTeamMembership) team() (*mqlPortainerTeam, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)
	teams, err := conn.Teams()
	if err != nil {
		return nil, err
	}
	for _, t := range teams {
		if t.ID == r.cacheTeamId {
			return newMqlPortainerTeam(r.MqlRuntime, t.ID, t.Name)
		}
	}
	// A membership can outlive its team, and the teams endpoint hides teams a
	// non-administrator token is not in. Creating a team resource from the id
	// alone would cache a team with an empty name under that id for the rest of
	// the scan, so report the reference as null instead.
	r.Team.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

// user resolves the account the membership belongs to.
func (r *mqlPortainerTeamMembership) user() (*mqlPortainerUser, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)
	users, err := conn.Users()
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.ID == r.cacheUserId {
			return newMqlPortainerUser(r.MqlRuntime, u)
		}
	}
	// The users endpoint hides administrator accounts from a non-administrator
	// token, and a membership can outlive its account.
	r.User.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}
