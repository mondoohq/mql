// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strconv"
	"strings"

	"github.com/google/go-github/v92/github"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/github/connection"
)

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
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
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
