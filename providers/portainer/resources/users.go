// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"github.com/portainer/client-api-go/v2/pkg/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/portainer/connection"
	"go.mondoo.com/mql/types"
)

// userTheme reads the account's UI theme. The top-level UserTheme field is
// deprecated; the value Portainer maintains lives in ThemeSettings, so prefer
// that and fall back to the legacy field for older instances.
func userTheme(u *models.PortainereeUser) string {
	if u.ThemeSettings != nil && u.ThemeSettings.Color != "" {
		return u.ThemeSettings.Color
	}
	return u.UserTheme
}

func newMqlPortainerUser(runtime *plugin.Runtime, u *models.PortainereeUser) (*mqlPortainerUser, error) {
	// An instance that does not compute authorizations reports none at all,
	// which is not the same as an account holding none, so an absent map stays
	// null instead of becoming an empty list.
	authorizations := llx.NilData
	if names, ok := grantedAuthorizations(u.PortainerAuthorizations); ok {
		authorizations = llx.ArrayData(names, types.String)
	}

	res, err := CreateResource(runtime, "portainer.user", map[string]*llx.RawData{
		"__id":           llx.StringData("portainer.user/" + strconv.FormatInt(u.ID, 10)),
		"id":             llx.IntData(u.ID),
		"username":       llx.StringData(u.Username),
		"role":           llx.StringData(connection.UserRole(u.Role)),
		"useCache":       llx.BoolData(u.UseCache),
		"theme":          llx.StringData(userTheme(u)),
		"tokenIssueAt":   llx.TimeDataPtr(unixTimePtr(u.TokenIssueAt)),
		"authorizations": authorizations,
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlPortainerUser), nil
}

func (r *mqlPortainer) users() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	users, err := conn.Users()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(users))
	for _, u := range users {
		mqlUser, err := newMqlPortainerUser(r.MqlRuntime, u)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlUser)
	}
	return res, nil
}

// teams returns the teams the user is a member of, resolved through the
// instance team memberships.
func (r *mqlPortainerUser) teams() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	memberships, err := conn.TeamMemberships()
	if err != nil {
		return nil, err
	}
	teams, err := conn.Teams()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, t := range userTeams(memberships, teams, r.Id.Data) {
		mqlTeam, err := newMqlPortainerTeam(r.MqlRuntime, t.ID, t.Name)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTeam)
	}
	return res, nil
}

// userTeams resolves the memberships of one user to the matching teams.
//
// A membership can reference a team that is not in the list: the teams endpoint
// only returns the caller's own teams for non-administrator tokens, and
// orphaned memberships outlive a deleted team. Those are skipped rather than
// emitting a team with an empty name, which would also poison the resource
// cache for that team id, since the first resource created under a given __id
// is the one every later lookup returns.
func userTeams(memberships []*models.PortainerTeamMembership, teams []*models.PortainerTeam, userID int64) []*models.PortainerTeam {
	teamByID := make(map[int64]*models.PortainerTeam, len(teams))
	for _, t := range teams {
		teamByID[t.ID] = t
	}

	res := []*models.PortainerTeam{}
	for _, m := range memberships {
		if m.UserID != userID {
			continue
		}
		if t, ok := teamByID[m.TeamID]; ok {
			res = append(res, t)
		}
	}
	return res
}
