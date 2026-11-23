// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strconv"
	"strings"
	"sync"

	"github.com/google/go-github/v93/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/github/connection"
)

type mqlGithubTeamInternal struct {
	// parentKnown is set when the team was built from a response that carries
	// the parent field, so a nil cacheParent means the team has no parent
	// rather than that the response left it out.
	parentKnown bool
	cacheParent *github.Team

	detailOnce sync.Once
	detail     *github.Team
	detailErr  error
}

// newMqlGithubTeam builds a team. withParent says whether the response the
// team came from reports its parent; the "team" representation GitHub returns
// from team listings does, the "team-simple" one nested in other objects does
// not.
func newMqlGithubTeam(runtime *plugin.Runtime, team *github.Team, organization *llx.RawData, withParent bool) (*mqlGithubTeam, error) {
	r, err := CreateResource(runtime, "github.team", map[string]*llx.RawData{
		"id":                  llx.IntDataPtr(team.ID),
		"name":                llx.StringDataPtr(team.Name),
		"description":         llx.StringDataPtr(team.Description),
		"slug":                llx.StringDataPtr(team.Slug),
		"privacy":             llx.StringDataPtr(team.Privacy),
		"defaultPermission":   llx.StringDataPtr(team.Permission),
		"type":                llx.StringDataPtr(team.Type),
		"notificationSetting": llx.StringDataPtr(team.NotificationSetting),
		"organization":        organization,
	})
	if err != nil {
		return nil, err
	}
	t := r.(*mqlGithubTeam)
	if withParent && !t.parentKnown {
		t.parentKnown = true
		t.cacheParent = team.Parent
	}
	return t, nil
}

// orgID returns the numeric id of the team's organization, which the by-id
// team endpoints address it by.
func (g *mqlGithubTeam) orgID() (int64, error) {
	if g.Organization.Error != nil {
		return 0, g.Organization.Error
	}
	org := g.Organization.Data
	if org == nil {
		return 0, errors.New("no organization specified")
	}
	if org.Id.Error != nil {
		return 0, org.Id.Error
	}
	return org.Id.Data, nil
}

func (g *mqlGithubTeam) organizationData() *llx.RawData {
	if g.Organization.Error != nil || g.Organization.Data == nil {
		return llx.NilData
	}
	return llx.ResourceData(g.Organization.Data, "github.organization")
}

// teamDetail reads the full team once. Only this endpoint reports the member
// and repository counts. A refused or missing team leaves the detail nil,
// which the fields render as null.
func (g *mqlGithubTeam) teamDetail() (*github.Team, error) {
	g.detailOnce.Do(func() {
		if g.Id.Error != nil {
			g.detailErr = g.Id.Error
			return
		}
		orgID, err := g.orgID()
		if err != nil {
			g.detailErr = err
			return
		}
		conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
		team, _, err := conn.Client().Teams.GetTeamByID(conn.Context(), orgID, g.Id.Data)
		if err != nil {
			if isAccessDeniedOrNotFound(err) {
				log.Debug().Err(err).Int64("team", g.Id.Data).Msg("team details are not accessible")
				return
			}
			g.detailErr = err
			return
		}
		g.detail = team
	})
	return g.detail, g.detailErr
}

func (g *mqlGithubTeam) parent() (*mqlGithubTeam, error) {
	var parent *github.Team
	if g.parentKnown {
		parent = g.cacheParent
	} else {
		detail, err := g.teamDetail()
		if err != nil {
			return nil, err
		}
		if detail != nil {
			parent = detail.Parent
		}
	}
	if parent == nil || parent.ID == nil {
		g.Parent.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// The parent arrives in the "team-simple" shape, which does not report
	// its own parent.
	return newMqlGithubTeam(g.MqlRuntime, parent, g.organizationData(), false)
}

func (g *mqlGithubTeam) childTeams() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	orgID, err := g.orgID()
	if err != nil {
		return nil, err
	}
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	orgData := g.organizationData()

	listOpts := &github.ListOptions{PerPage: paginationPerPage}
	res := []any{}
	for {
		teams, resp, err := conn.Client().Teams.ListChildTeamsByParentID(conn.Context(), orgID, g.Id.Data, listOpts)
		if err != nil {
			if isAccessDeniedOrNotFound(err) {
				log.Debug().Err(err).Int64("team", g.Id.Data).Msg("child teams are not accessible")
				g.ChildTeams.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, err
		}
		for _, team := range teams {
			t, err := newMqlGithubTeam(g.MqlRuntime, team, orgData, true)
			if err != nil {
				return nil, err
			}
			res = append(res, t)
		}
		next := nextPage(listOpts.Page, resp)
		if next == 0 {
			break
		}
		listOpts.Page = next
	}
	return res, nil
}

func (g *mqlGithubTeam) membersCount() (int64, error) {
	detail, err := g.teamDetail()
	if err != nil {
		return 0, err
	}
	var v *int
	if detail != nil {
		v = detail.MembersCount
	}
	return optionalInt(v, &g.MembersCount)
}

func (g *mqlGithubTeam) reposCount() (int64, error) {
	detail, err := g.teamDetail()
	if err != nil {
		return 0, err
	}
	var v *int
	if detail != nil {
		v = detail.ReposCount
	}
	return optionalInt(v, &g.ReposCount)
}

func (g *mqlGithubTeam) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return "github.team/" + strconv.FormatInt(id, 10), nil
}

func (g *mqlGithubTeam) repositories() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	teamID := g.Id.Data

	if g.Organization.Error != nil {
		return nil, g.Organization.Error
	}
	org := g.Organization.Data

	if org.Id.Error != nil {
		return nil, org.Id.Error
	}
	orgID := org.Id.Data

	listOpts := &github.ListOptions{PerPage: paginationPerPage}
	var allRepos []*github.Repository
	for {
		repos, resp, err := conn.Client().Teams.ListTeamReposByID(conn.Context(), orgID, teamID, listOpts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			return nil, err
		}
		allRepos = append(allRepos, repos...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := []any{}
	for i := range allRepos {
		repo := allRepos[i]

		r, err := newMqlGithubRepository(g.MqlRuntime, repo)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}

	return res, nil
}

func (g *mqlGithubTeam) members() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	teamID := g.Id.Data

	if g.Organization.Error != nil {
		return nil, g.Organization.Error
	}
	org := g.Organization.Data
	if org == nil {
		return nil, errors.New("no organization specified")
	}
	if org.Id.Error != nil {
		return nil, org.Id.Error
	}
	orgID := org.Id.Data

	listOpts := &github.TeamListTeamMembersOptions{
		PerPage: paginationPerPage,
	}
	var allMembers []*github.User
	for {
		members, resp, err := conn.Client().Teams.ListTeamMembersByID(conn.Context(), orgID, teamID, listOpts)
		if err != nil {
			// A team that's gone (deleted between list and access) or not
			// visible to the token 404s; degrade to an empty member list
			// rather than failing the whole query, like team.repositories().
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			return nil, err
		}
		allMembers = append(allMembers, members...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := []any{}
	for i := range allMembers {
		member := allMembers[i]

		r, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
			"id":    llx.IntDataPtr(member.ID),
			"login": llx.StringDataPtr(member.Login),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}

	return res, nil
}
