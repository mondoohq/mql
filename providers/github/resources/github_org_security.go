// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"github.com/google/go-github/v92/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/github/connection"
)

// securityManagerTeams returns the teams holding the organization's security
// manager role. The role grants read on every repository in the organization
// and write on its security alerts, independent of the repository permissions
// the team is granted elsewhere, so membership of one of these teams is an
// org-wide standing grant that no per-repository check surfaces.
//
// Empty when GitHub answers with no teams, which is the genuine "nobody holds
// the role" case. Null when the role cannot be read at all, so a token without
// organization admin access does not report an unguarded org as clean.
func (g *mqlGithubOrganization) securityManagerTeams() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	// This endpoint takes no ListOptions and so cannot be paged: the SDK
	// signature is ListSecurityManagerTeams(ctx, org), and GitHub returns the
	// whole set. collectPages has nothing to iterate here.
	//
	// The method is marked deprecated in favour of ListTeamsAssignedToOrgRole,
	// which does page. Migrating is not a like-for-like swap: that call is keyed
	// on a numeric role id, so it first needs the security-manager role resolved
	// out of the org role list by name. Getting that name wrong returns an empty
	// list rather than an error, which would report "no security managers" as
	// fact, so the swap wants verifying against a live org before it lands.
	teams, _, err := conn.Client().Organizations.ListSecurityManagerTeams(conn.Context(), orgLogin)
	if err != nil {
		switch {
		case githubForbidden(err):
			log.Warn().Err(err).Str("org", orgLogin).
				Msg("permission denied reading security manager teams; reporting them as unknown")
		case githubNotAvailable(err):
			log.Debug().Err(err).Str("org", orgLogin).
				Msg("security manager teams are not available for this organization")
		default:
			return nil, err
		}
		g.SecurityManagerTeams.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := make([]any, 0, len(teams))
	for _, team := range teams {
		r, err := CreateResource(g.MqlRuntime, "github.team", map[string]*llx.RawData{
			"id":                llx.IntDataPtr(team.ID),
			"name":              llx.StringDataPtr(team.Name),
			"description":       llx.StringDataPtr(team.Description),
			"slug":              llx.StringDataPtr(team.Slug),
			"privacy":           llx.StringDataPtr(team.Privacy),
			"defaultPermission": llx.StringDataPtr(team.Permission),
			"type":              llx.StringDataPtr(team.Type),
			"organization":      llx.ResourceData(g, g.MqlName()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// ---------- immutable releases ----------

type mqlGithubOrganizationImmutableReleasesInternal struct {
	orgLogin string
}

func (g *mqlGithubOrganizationImmutableReleases) id() (string, error) {
	return g.__id, nil
}

// initGithubOrganizationImmutableReleases delegates to the organization so the
// dotted path resolves to the same populated resource the organization field
// hands out rather than instantiating a blank one.
func initGithubOrganizationImmutableReleases(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	org, err := NewResource(runtime, "github.organization", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	settings := org.(*mqlGithubOrganization).GetImmutableReleases()
	if settings.Error != nil {
		return nil, nil, settings.Error
	}
	if settings.Data == nil {
		return nil, nil, errors.New("immutable release settings are not readable for this organization")
	}
	return args, settings.Data, nil
}

// immutableReleases reports whether a published release's tag and assets can
// still be replaced. Null when the setting cannot be read, because reporting an
// unread organization as unenforced would clear it on a control nobody checked.
func (g *mqlGithubOrganization) immutableReleases() (*mqlGithubOrganizationImmutableReleases, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	settings, _, err := conn.Client().Organizations.GetImmutableReleasesSettings(conn.Context(), orgLogin)
	if err != nil {
		switch {
		case githubForbidden(err):
			log.Warn().Err(err).Str("org", orgLogin).
				Msg("permission denied reading immutable release settings; reporting them as unknown")
		case githubNotAvailable(err):
			log.Debug().Err(err).Str("org", orgLogin).
				Msg("immutable release settings are not available for this organization")
		default:
			return nil, err
		}
		g.ImmutableReleases.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if settings == nil {
		g.ImmutableReleases.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(g.MqlRuntime, "github.organization.immutableReleases", map[string]*llx.RawData{
		"__id":                 llx.StringData("github.organization.immutableReleases/" + orgLogin),
		"enforcedRepositories": llx.StringDataPtr(settings.EnforcedRepositories),
	})
	if err != nil {
		return nil, err
	}
	mqlSettings := res.(*mqlGithubOrganizationImmutableReleases)
	mqlSettings.orgLogin = orgLogin
	return mqlSettings, nil
}

// selectedRepositories lists the repositories immutable releases are enforced
// on. Null unless the enforcement scope is "selected": with a scope of all or
// none there is no selection, and an empty list would read as "enforced
// nowhere" on an organization that enforces it everywhere.
func (g *mqlGithubOrganizationImmutableReleases) selectedRepositories() ([]any, error) {
	if g.EnforcedRepositories.Error != nil {
		return nil, g.EnforcedRepositories.Error
	}
	if g.EnforcedRepositories.Data != "selected" {
		g.SelectedRepositories.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	all, err := collectPages(func(opts *github.ListOptions) ([]*github.Repository, *github.Response, error) {
		page, resp, err := conn.Client().Organizations.ListImmutableReleaseRepositories(conn.Context(), g.orgLogin, opts)
		if err != nil {
			return nil, resp, err
		}
		return page.Repositories, resp, nil
	})
	if err != nil {
		if githubForbidden(err) || githubNotAvailable(err) {
			log.Debug().Err(err).Str("org", g.orgLogin).
				Msg("repositories selected for immutable releases are not readable")
			g.SelectedRepositories.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return reposToMql(g.MqlRuntime, all)
}
