// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"github.com/google/go-github/v93/github"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/github/connection"
)

// ---------- Codespaces secrets ----------

// Codespaces keeps a secret store of its own, separate from the Actions,
// Dependabot and Copilot cloud agent stores. Its secrets become environment
// variables inside a codespace, so they reach whoever can open one. Only
// names, scope, visibility and timestamps are read here; the values are never
// exposed by the API and are never modelled.

type mqlGithubCodespacesSecretInternal struct {
	orgLogin string
}

func (g *mqlGithubCodespacesSecret) id() (string, error) {
	return g.__id, nil
}

// codespacesSecretID keys a secret by the store it lives in. Secret names
// repeat freely across repositories and between a repository and its
// organization, so an unqualified name collides.
func codespacesSecretID(scope, owner, repo, name string) string {
	if scope == scopeOrganization {
		return "github.codespacesSecret/org/" + owner + "/" + name
	}
	return "github.codespacesSecret/repo/" + owner + "/" + repo + "/" + name
}

// codespacesSecrets returns the organization-level Codespaces secrets.
func (g *mqlGithubOrganization) codespacesSecrets() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	all, err := collectPages(func(opts *github.ListOptions) ([]*github.Secret, *github.Response, error) {
		page, resp, err := conn.Client().Codespaces.ListOrgSecrets(conn.Context(), orgLogin, opts)
		if err != nil {
			return nil, resp, err
		}
		return page.Secrets, resp, nil
	})
	if err != nil {
		if err := classifyReadErr(err, "organization Codespaces secrets", orgLogin); err != nil {
			return nil, err
		}
		g.CodespacesSecrets.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := make([]any, 0, len(all))
	for _, s := range all {
		r, err := CreateResource(g.MqlRuntime, "github.codespacesSecret", map[string]*llx.RawData{
			"__id":             llx.StringData(codespacesSecretID(scopeOrganization, orgLogin, "", s.Name)),
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
		r.(*mqlGithubCodespacesSecret).orgLogin = orgLogin
		res = append(res, r)
	}
	return res, nil
}

// codespacesSecrets returns the repository-level Codespaces secrets. A
// repository store has no visibility of its own, so visibility stays empty
// here; the field only carries meaning for an organization secret.
func (g *mqlGithubRepository) codespacesSecrets() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	owner, repo, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	all, err := collectPages(func(opts *github.ListOptions) ([]*github.Secret, *github.Response, error) {
		page, resp, err := conn.Client().Codespaces.ListRepoSecrets(conn.Context(), owner, repo, opts)
		if err != nil {
			return nil, resp, err
		}
		return page.Secrets, resp, nil
	})
	if err != nil {
		if err := classifyReadErr(err, "repository Codespaces secrets", owner+"/"+repo); err != nil {
			return nil, err
		}
		g.CodespacesSecrets.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := make([]any, 0, len(all))
	for _, s := range all {
		r, err := CreateResource(g.MqlRuntime, "github.codespacesSecret", map[string]*llx.RawData{
			"__id":             llx.StringData(codespacesSecretID(scopeRepository, owner, repo, s.Name)),
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
func (g *mqlGithubCodespacesSecret) selectedRepositories() ([]any, error) {
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
		page, resp, err := conn.Client().Codespaces.ListSelectedReposForOrgSecret(conn.Context(), g.orgLogin, g.Name.Data, opts)
		if err != nil {
			return nil, resp, err
		}
		return page.Repositories, resp, nil
	})
	if err != nil {
		if err := classifyReadErr(err, "Codespaces secret repositories", g.orgLogin); err != nil {
			return nil, err
		}
		g.SelectedRepositories.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return reposToMql(g.MqlRuntime, all)
}

// ---------- Codespaces inventory ----------

type mqlGithubCodespaceInternal struct {
	cacheCodespace *github.Codespace
}

func (g *mqlGithubCodespace) id() (string, error) {
	return g.__id, nil
}

func codespaceArgs(orgLogin string, c *github.Codespace) map[string]*llx.RawData {
	m := c.Machine
	if m == nil {
		m = &github.CodespacesMachine{}
	}
	return map[string]*llx.RawData{
		"__id":                   llx.StringData("github.codespace/" + orgLogin + "/" + strconv.FormatInt(c.GetID(), 10)),
		"id":                     llx.IntDataPtr(c.ID),
		"name":                   llx.StringDataPtr(c.Name),
		"displayName":            llx.StringDataPtr(c.DisplayName),
		"state":                  llx.StringDataPtr(c.State),
		"machineName":            llx.StringDataPtr(m.Name),
		"machineDisplayName":     llx.StringDataPtr(m.DisplayName),
		"machineOperatingSystem": llx.StringDataPtr(m.OperatingSystem),
		"machineCpus":            intPtrData(m.CPUs),
		"machineMemoryInBytes":   llx.IntDataPtr(m.MemoryInBytes),
		"machineStorageInBytes":  llx.IntDataPtr(m.StorageInBytes),
		"devcontainerPath":       llx.StringDataPtr(c.DevcontainerPath),
		"prebuild":               llx.BoolDataPtr(c.Prebuild),
		"idleTimeoutMinutes":     intPtrData(c.IdleTimeoutMinutes),
		"retentionPeriodMinutes": intPtrData(c.RetentionPeriodMinutes),
		"retentionExpiresAt":     llx.TimeDataPtr(githubTime(c.RetentionExpiresAt)),
		"createdAt":              llx.TimeDataPtr(githubTime(c.CreatedAt)),
		"updatedAt":              llx.TimeDataPtr(githubTime(c.UpdatedAt)),
		"lastUsedAt":             llx.TimeDataPtr(githubTime(c.LastUsedAt)),
	}
}

func (g *mqlGithubOrganization) codespaces() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	all, err := collectPages(func(opts *github.ListOptions) ([]*github.Codespace, *github.Response, error) {
		page, resp, err := conn.Client().Codespaces.ListInOrg(conn.Context(), orgLogin, opts)
		if err != nil {
			return nil, resp, err
		}
		return page.Codespaces, resp, nil
	})
	if err != nil {
		if err := classifyReadErr(err, "organization codespaces", orgLogin); err != nil {
			return nil, err
		}
		g.Codespaces.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := make([]any, 0, len(all))
	for _, c := range all {
		if c == nil || c.ID == nil {
			continue
		}
		r, err := CreateResource(g.MqlRuntime, "github.codespace", codespaceArgs(orgLogin, c))
		if err != nil {
			return nil, err
		}
		r.(*mqlGithubCodespace).cacheCodespace = c
		res = append(res, r)
	}
	return res, nil
}

func (g *mqlGithubCodespace) owner() (*mqlGithubUser, error) {
	return embeddedUser(g.MqlRuntime, g.cacheCodespace.GetOwner(), &g.Owner)
}

func (g *mqlGithubCodespace) billableOwner() (*mqlGithubUser, error) {
	return embeddedUser(g.MqlRuntime, g.cacheCodespace.GetBillableOwner(), &g.BillableOwner)
}

func (g *mqlGithubCodespace) repository() (*mqlGithubRepository, error) {
	repo := g.cacheCodespace.GetRepository()
	if repo == nil || repo.ID == nil {
		g.Repository.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlGithubRepository(g.MqlRuntime, repo)
}
