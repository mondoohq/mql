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

// The Copilot cloud agent reads its own secret store (the REST API calls it
// "agents"), separate from Actions, Codespaces and Dependabot. Only names,
// scope, visibility and timestamps are read here; the API never returns the
// values and they are never modelled.

type mqlGithubAgentSecretInternal struct {
	orgLogin string
}

func (g *mqlGithubAgentSecret) id() (string, error) {
	return g.__id, nil
}

// agentSecretID keys a secret by the store it lives in. Secret names repeat
// freely across repositories and between a repository and its organization,
// so an unqualified name collides.
func agentSecretID(scope, owner, repo, name string) string {
	if scope == scopeOrganization {
		return "github.agentSecret/org/" + owner + "/" + name
	}
	return "github.agentSecret/repo/" + owner + "/" + repo + "/" + name
}

// classifyAgentSecretsError decides what a failed agent secrets listing
// reports. A refusal is an access-denied error, since the secrets that exist
// are unknown. A 404 or 409 means the store is not available to this owner
// and reads as no store at all (nil error, null field). Anything else is
// returned unchanged.
func classifyAgentSecretsError(err error) (absent bool, out error) {
	if githubForbidden(err) {
		return false, llx.Forbidden(err)
	}
	if githubNotAvailable(err) {
		return true, nil
	}
	return false, err
}

// agentSecrets returns the organization-level Copilot cloud agent secrets.
func (g *mqlGithubOrganization) agentSecrets() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	all, err := collectPages(func(opts *github.ListOptions) ([]*github.Secret, *github.Response, error) {
		page, resp, err := conn.Client().Agents.ListOrgSecrets(conn.Context(), orgLogin, opts)
		if err != nil {
			return nil, resp, err
		}
		return page.Secrets, resp, nil
	})
	if err != nil {
		absent, cerr := classifyAgentSecretsError(err)
		if !absent {
			return nil, cerr
		}
		log.Debug().Err(err).Str("org", orgLogin).
			Msg("organization agent secrets are not available")
		g.AgentSecrets.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := make([]any, 0, len(all))
	for _, s := range all {
		if s == nil {
			continue
		}
		r, err := CreateResource(g.MqlRuntime, "github.agentSecret", map[string]*llx.RawData{
			"__id":             llx.StringData(agentSecretID(scopeOrganization, orgLogin, "", s.Name)),
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
		r.(*mqlGithubAgentSecret).orgLogin = orgLogin
		res = append(res, r)
	}
	return res, nil
}

// agentSecrets returns the repository-level Copilot cloud agent secrets. A
// repository store has no visibility of its own, so visibility stays empty
// here; the field only carries meaning for an organization secret.
func (g *mqlGithubRepository) agentSecrets() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	owner, repo, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	all, err := collectPages(func(opts *github.ListOptions) ([]*github.Secret, *github.Response, error) {
		page, resp, err := conn.Client().Agents.ListRepoSecrets(conn.Context(), owner, repo, opts)
		if err != nil {
			return nil, resp, err
		}
		return page.Secrets, resp, nil
	})
	if err != nil {
		absent, cerr := classifyAgentSecretsError(err)
		if !absent {
			return nil, cerr
		}
		log.Debug().Err(err).Str("owner", owner).Str("repo", repo).
			Msg("repository agent secrets are not available")
		g.AgentSecrets.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := make([]any, 0, len(all))
	for _, s := range all {
		if s == nil {
			continue
		}
		r, err := CreateResource(g.MqlRuntime, "github.agentSecret", map[string]*llx.RawData{
			"__id":             llx.StringData(agentSecretID(scopeRepository, owner, repo, s.Name)),
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
func (g *mqlGithubAgentSecret) selectedRepositories() ([]any, error) {
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
		page, resp, err := conn.Client().Agents.ListSelectedReposForOrgSecret(conn.Context(), g.orgLogin, g.Name.Data, opts)
		if err != nil {
			return nil, resp, err
		}
		return page.Repositories, resp, nil
	})
	if err != nil {
		if githubForbidden(err) {
			return nil, llx.Forbidden(err)
		}
		return nil, err
	}
	return reposToMql(g.MqlRuntime, all)
}
