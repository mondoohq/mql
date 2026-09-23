// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/google/go-github/v92/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/github/connection"
)

// Dependabot keeps a secret store of its own, separate from the Actions store
// github.actionsSecret reports. The credentials in it are the ones Dependabot
// presents to private package registries while resolving a dependency, so they
// are reachable from dependency resolution rather than from a workflow run.
// Only names, scope, visibility and timestamps are read here; the values are
// never exposed by the API and are never modelled.

type mqlGithubDependabotSecretInternal struct {
	orgLogin string
}

func (g *mqlGithubDependabotSecret) id() (string, error) {
	return g.__id, nil
}

// dependabotSecretID keys a secret by the store it lives in. Secret names
// repeat freely across repositories and between a repository and its
// organization, so an unqualified name collides.
func dependabotSecretID(scope, owner, repo, name string) string {
	if scope == scopeOrganization {
		return "github.dependabotSecret/org/" + owner + "/" + name
	}
	return "github.dependabotSecret/repo/" + owner + "/" + repo + "/" + name
}

// dependabotSecrets returns the organization-level Dependabot secrets.
func (g *mqlGithubOrganization) dependabotSecrets() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	all, err := collectPages(func(opts *github.ListOptions) ([]*github.Secret, *github.Response, error) {
		page, resp, err := conn.Client().Dependabot.ListOrgSecrets(conn.Context(), orgLogin, opts)
		if err != nil {
			return nil, resp, err
		}
		return page.Secrets, resp, nil
	})
	if err != nil {
		if githubForbidden(err) {
			log.Warn().Err(err).Str("org", orgLogin).
				Msg("permission denied reading organization Dependabot secrets; reporting them as unknown")
		} else if githubNotAvailable(err) {
			log.Debug().Err(err).Str("org", orgLogin).
				Msg("organization Dependabot secrets are not available")
		} else {
			return nil, err
		}
		g.DependabotSecrets.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := make([]any, 0, len(all))
	for _, s := range all {
		r, err := CreateResource(g.MqlRuntime, "github.dependabotSecret", map[string]*llx.RawData{
			"__id":             llx.StringData(dependabotSecretID(scopeOrganization, orgLogin, "", s.Name)),
			"name":             llx.StringData(s.Name),
			"scope":            llx.StringData(scopeOrganization),
			"organizationName": llx.StringData(orgLogin),
			"repositoryName":   llx.StringData(""),
			"repositoryOwner":  llx.StringData(""),
			"createdAt":        llx.TimeDataPtr(githubTimeValue(s.CreatedAt)),
			"updatedAt":        llx.TimeDataPtr(githubTimeValue(s.UpdatedAt)),
			"visibility":       llx.StringData(s.Visibility),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlGithubDependabotSecret).orgLogin = orgLogin
		res = append(res, r)
	}
	return res, nil
}

// dependabotSecrets returns the repository-level Dependabot secrets. A
// repository store has no visibility of its own, so visibility stays empty
// here; the field only carries meaning for an organization secret.
func (g *mqlGithubRepository) dependabotSecrets() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	owner, repo, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	all, err := collectPages(func(opts *github.ListOptions) ([]*github.Secret, *github.Response, error) {
		page, resp, err := conn.Client().Dependabot.ListRepoSecrets(conn.Context(), owner, repo, opts)
		if err != nil {
			return nil, resp, err
		}
		return page.Secrets, resp, nil
	})
	if err != nil {
		if githubForbidden(err) {
			log.Warn().Err(err).Str("owner", owner).Str("repo", repo).
				Msg("permission denied reading repository Dependabot secrets; reporting them as unknown")
		} else if githubNotAvailable(err) {
			log.Debug().Err(err).Str("owner", owner).Str("repo", repo).
				Msg("repository Dependabot secrets are not available")
		} else {
			return nil, err
		}
		g.DependabotSecrets.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := make([]any, 0, len(all))
	for _, s := range all {
		r, err := CreateResource(g.MqlRuntime, "github.dependabotSecret", map[string]*llx.RawData{
			"__id":             llx.StringData(dependabotSecretID(scopeRepository, owner, repo, s.Name)),
			"name":             llx.StringData(s.Name),
			"scope":            llx.StringData(scopeRepository),
			"organizationName": llx.StringData(""),
			"repositoryName":   llx.StringData(repo),
			"repositoryOwner":  llx.StringData(owner),
			"createdAt":        llx.TimeDataPtr(githubTimeValue(s.CreatedAt)),
			"updatedAt":        llx.TimeDataPtr(githubTimeValue(s.UpdatedAt)),
			"visibility":       llx.StringData(""),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// selectedRepositories lists the repositories an organization secret with
// "selected" visibility is shared with. Null for a repository secret and for an
// organization secret whose visibility already covers every repository, where
// no per-repository selection exists to report.
func (g *mqlGithubDependabotSecret) selectedRepositories() ([]any, error) {
	if g.Scope.Error != nil {
		return nil, g.Scope.Error
	}
	if g.Visibility.Error != nil {
		return nil, g.Visibility.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	if g.Scope.Data != scopeOrganization || g.Visibility.Data != "selected" {
		g.SelectedRepositories.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	all, err := collectPages(func(opts *github.ListOptions) ([]*github.Repository, *github.Response, error) {
		page, resp, err := conn.Client().Dependabot.ListSelectedReposForOrgSecret(conn.Context(), g.orgLogin, g.Name.Data, opts)
		if err != nil {
			return nil, resp, err
		}
		return page.Repositories, resp, nil
	})
	if err != nil {
		if githubForbidden(err) || githubNotAvailable(err) {
			log.Debug().Err(err).Str("org", g.orgLogin).Str("secret", g.Name.Data).
				Msg("selected repositories for the Dependabot secret are not readable")
			g.SelectedRepositories.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return reposToMql(g.MqlRuntime, all)
}
