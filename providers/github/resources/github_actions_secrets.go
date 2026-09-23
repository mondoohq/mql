// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/google/go-github/v92/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/github/connection"
)

const (
	scopeOrganization = "organization"
	scopeRepository   = "repository"
	scopeEnvironment  = "environment"
)

func (g *mqlGithubActionsSecret) id() (string, error) {
	return g.__id, nil
}

func (g *mqlGithubActionsVariable) id() (string, error) {
	return g.__id, nil
}

type mqlGithubActionsSecretInternal struct {
	selectedReposURL string
	orgLogin         string
}

type mqlGithubActionsVariableInternal struct {
	selectedReposURL string
	orgLogin         string
}

func actionsSecretID(scope, owner, repo, env, name string) string {
	switch scope {
	case scopeOrganization:
		return "github.actionsSecret/org/" + owner + "/" + name
	case scopeEnvironment:
		return "github.actionsSecret/repo/" + owner + "/" + repo + "/env/" + env + "/" + name
	default:
		return "github.actionsSecret/repo/" + owner + "/" + repo + "/" + name
	}
}

func actionsVariableID(scope, owner, repo, env, name string) string {
	switch scope {
	case scopeOrganization:
		return "github.actionsVariable/org/" + owner + "/" + name
	case scopeEnvironment:
		return "github.actionsVariable/repo/" + owner + "/" + repo + "/env/" + env + "/" + name
	default:
		return "github.actionsVariable/repo/" + owner + "/" + repo + "/" + name
	}
}

// secrets returns organization-level GitHub Actions secrets.
func (g *mqlGithubOrganization) secrets() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	opts := &github.ListOptions{PerPage: paginationPerPage}
	var all []*github.Secret
	for {
		page, resp, err := conn.Client().Actions.ListOrgSecrets(conn.Context(), orgLogin, opts)
		if err != nil {
			return handleActionsListErr(err, "organization secrets")
		}
		all = append(all, page.Secrets...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	res := make([]any, 0, len(all))
	for _, s := range all {
		args := map[string]*llx.RawData{
			"__id":                    llx.StringData(actionsSecretID(scopeOrganization, orgLogin, "", "", s.Name)),
			"name":                    llx.StringData(s.Name),
			"scope":                   llx.StringData(scopeOrganization),
			"organizationName":        llx.StringData(orgLogin),
			"repositoryName":          llx.StringData(""),
			"repositoryOwner":         llx.StringData(""),
			"environmentName":         llx.StringData(""),
			"createdAt":               llx.TimeData(s.CreatedAt.Time),
			"updatedAt":               llx.TimeData(s.UpdatedAt.Time),
			"visibility":              llx.StringData(s.Visibility),
			"selectedRepositoriesUrl": llx.StringData(s.SelectedRepositoriesURL),
		}
		secret, err := CreateResource(g.MqlRuntime, "github.actionsSecret", args)
		if err != nil {
			return nil, err
		}
		mqlSecret := secret.(*mqlGithubActionsSecret)
		mqlSecret.orgLogin = orgLogin
		mqlSecret.selectedReposURL = s.SelectedRepositoriesURL
		res = append(res, mqlSecret)
	}
	return res, nil
}

// variables returns organization-level GitHub Actions variables.
func (g *mqlGithubOrganization) variables() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	opts := &github.ListOptions{PerPage: paginationPerPage}
	var all []*github.ActionsVariable
	for {
		page, resp, err := conn.Client().Actions.ListOrgVariables(conn.Context(), orgLogin, opts)
		if err != nil {
			return handleActionsListErr(err, "organization variables")
		}
		all = append(all, page.Variables...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	res := make([]any, 0, len(all))
	for _, v := range all {
		args := map[string]*llx.RawData{
			"__id":                    llx.StringData(actionsVariableID(scopeOrganization, orgLogin, "", "", v.Name)),
			"name":                    llx.StringData(v.Name),
			"value":                   llx.StringData(v.Value),
			"scope":                   llx.StringData(scopeOrganization),
			"organizationName":        llx.StringData(orgLogin),
			"repositoryName":          llx.StringData(""),
			"repositoryOwner":         llx.StringData(""),
			"environmentName":         llx.StringData(""),
			"createdAt":               llx.TimeDataPtr(githubTimestamp(v.CreatedAt)),
			"updatedAt":               llx.TimeDataPtr(githubTimestamp(v.UpdatedAt)),
			"visibility":              llx.StringDataPtr(v.Visibility),
			"selectedRepositoriesUrl": llx.StringDataPtr(v.SelectedRepositoriesURL),
		}
		variable, err := CreateResource(g.MqlRuntime, "github.actionsVariable", args)
		if err != nil {
			return nil, err
		}
		mqlVar := variable.(*mqlGithubActionsVariable)
		mqlVar.orgLogin = orgLogin
		if v.SelectedRepositoriesURL != nil {
			mqlVar.selectedReposURL = *v.SelectedRepositoriesURL
		}
		res = append(res, mqlVar)
	}
	return res, nil
}

// secrets returns repository-level GitHub Actions secrets.
func (g *mqlGithubRepository) secrets() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	owner, repo, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	opts := &github.ListOptions{PerPage: paginationPerPage}
	var all []*github.Secret
	for {
		page, resp, err := conn.Client().Actions.ListRepoSecrets(conn.Context(), owner, repo, opts)
		if err != nil {
			return handleActionsListErr(err, "repository secrets")
		}
		all = append(all, page.Secrets...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	res := make([]any, 0, len(all))
	for _, s := range all {
		args := map[string]*llx.RawData{
			"__id":                    llx.StringData(actionsSecretID(scopeRepository, owner, repo, "", s.Name)),
			"name":                    llx.StringData(s.Name),
			"scope":                   llx.StringData(scopeRepository),
			"organizationName":        llx.StringData(""),
			"repositoryName":          llx.StringData(repo),
			"repositoryOwner":         llx.StringData(owner),
			"environmentName":         llx.StringData(""),
			"createdAt":               llx.TimeData(s.CreatedAt.Time),
			"updatedAt":               llx.TimeData(s.UpdatedAt.Time),
			"visibility":              llx.StringData(""),
			"selectedRepositoriesUrl": llx.StringData(""),
		}
		secret, err := CreateResource(g.MqlRuntime, "github.actionsSecret", args)
		if err != nil {
			return nil, err
		}
		res = append(res, secret)
	}
	return res, nil
}

// variables returns repository-level GitHub Actions variables.
func (g *mqlGithubRepository) variables() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	owner, repo, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	opts := &github.ListOptions{PerPage: paginationPerPage}
	var all []*github.ActionsVariable
	for {
		page, resp, err := conn.Client().Actions.ListRepoVariables(conn.Context(), owner, repo, opts)
		if err != nil {
			return handleActionsListErr(err, "repository variables")
		}
		all = append(all, page.Variables...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	res := make([]any, 0, len(all))
	for _, v := range all {
		args := map[string]*llx.RawData{
			"__id":                    llx.StringData(actionsVariableID(scopeRepository, owner, repo, "", v.Name)),
			"name":                    llx.StringData(v.Name),
			"value":                   llx.StringData(v.Value),
			"scope":                   llx.StringData(scopeRepository),
			"organizationName":        llx.StringData(""),
			"repositoryName":          llx.StringData(repo),
			"repositoryOwner":         llx.StringData(owner),
			"environmentName":         llx.StringData(""),
			"createdAt":               llx.TimeDataPtr(githubTimestamp(v.CreatedAt)),
			"updatedAt":               llx.TimeDataPtr(githubTimestamp(v.UpdatedAt)),
			"visibility":              llx.StringData(""),
			"selectedRepositoriesUrl": llx.StringData(""),
		}
		variable, err := CreateResource(g.MqlRuntime, "github.actionsVariable", args)
		if err != nil {
			return nil, err
		}
		res = append(res, variable)
	}
	return res, nil
}

// secrets returns environment-level GitHub Actions secrets.
func (g *mqlGithubEnvironment) secrets() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	envName := g.Name.Data
	owner := g.ownerLogin
	repo := g.repoName
	repoID := g.repoID

	if owner == "" || repo == "" || repoID == 0 || envName == "" {
		return nil, nil
	}

	opts := &github.ListOptions{PerPage: paginationPerPage}
	var all []*github.Secret
	for {
		page, resp, err := conn.Client().Actions.ListEnvSecrets(conn.Context(), owner, repo, envName, opts)
		if err != nil {
			return handleActionsListErr(err, "environment secrets")
		}
		all = append(all, page.Secrets...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	res := make([]any, 0, len(all))
	for _, s := range all {
		args := map[string]*llx.RawData{
			"__id":                    llx.StringData(actionsSecretID(scopeEnvironment, owner, repo, envName, s.Name)),
			"name":                    llx.StringData(s.Name),
			"scope":                   llx.StringData(scopeEnvironment),
			"organizationName":        llx.StringData(""),
			"repositoryName":          llx.StringData(repo),
			"repositoryOwner":         llx.StringData(owner),
			"environmentName":         llx.StringData(envName),
			"createdAt":               llx.TimeData(s.CreatedAt.Time),
			"updatedAt":               llx.TimeData(s.UpdatedAt.Time),
			"visibility":              llx.StringData(""),
			"selectedRepositoriesUrl": llx.StringData(""),
		}
		secret, err := CreateResource(g.MqlRuntime, "github.actionsSecret", args)
		if err != nil {
			return nil, err
		}
		res = append(res, secret)
	}
	return res, nil
}

// variables returns environment-level GitHub Actions variables.
func (g *mqlGithubEnvironment) variables() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	envName := g.Name.Data
	owner := g.ownerLogin
	repo := g.repoName
	repoID := g.repoID

	if owner == "" || repo == "" || repoID == 0 || envName == "" {
		return nil, nil
	}

	opts := &github.ListOptions{PerPage: paginationPerPage}
	var all []*github.ActionsVariable
	for {
		page, resp, err := conn.Client().Actions.ListEnvVariables(conn.Context(), owner, repo, envName, opts)
		if err != nil {
			return handleActionsListErr(err, "environment variables")
		}
		all = append(all, page.Variables...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	res := make([]any, 0, len(all))
	for _, v := range all {
		args := map[string]*llx.RawData{
			"__id":                    llx.StringData(actionsVariableID(scopeEnvironment, owner, repo, envName, v.Name)),
			"name":                    llx.StringData(v.Name),
			"value":                   llx.StringData(v.Value),
			"scope":                   llx.StringData(scopeEnvironment),
			"organizationName":        llx.StringData(""),
			"repositoryName":          llx.StringData(repo),
			"repositoryOwner":         llx.StringData(owner),
			"environmentName":         llx.StringData(envName),
			"createdAt":               llx.TimeDataPtr(githubTimestamp(v.CreatedAt)),
			"updatedAt":               llx.TimeDataPtr(githubTimestamp(v.UpdatedAt)),
			"visibility":              llx.StringData(""),
			"selectedRepositoriesUrl": llx.StringData(""),
		}
		variable, err := CreateResource(g.MqlRuntime, "github.actionsVariable", args)
		if err != nil {
			return nil, err
		}
		res = append(res, variable)
	}
	return res, nil
}

// selectedRepositories lists the repositories an organization secret with "selected"
// visibility has been shared with. Returns nil for non-org-scoped secrets or when
// visibility is not "selected".
func (g *mqlGithubActionsSecret) selectedRepositories() ([]any, error) {
	if g.Scope.Error != nil {
		return nil, g.Scope.Error
	}
	if g.Scope.Data != scopeOrganization {
		return nil, nil
	}
	if g.Visibility.Error != nil {
		return nil, g.Visibility.Error
	}
	if g.Visibility.Data != "selected" {
		return nil, nil
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}

	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	opts := &github.ListOptions{PerPage: paginationPerPage}
	var all []*github.Repository
	for {
		page, resp, err := conn.Client().Actions.ListSelectedReposForOrgSecret(conn.Context(), g.orgLogin, g.Name.Data, opts)
		if err != nil {
			return handleActionsListErr(err, "selected repositories for secret")
		}
		all = append(all, page.Repositories...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return reposToMql(g.MqlRuntime, all)
}

// selectedRepositories lists the repositories an organization variable with "selected"
// visibility has been shared with. Returns nil for non-org-scoped variables or when
// visibility is not "selected".
func (g *mqlGithubActionsVariable) selectedRepositories() ([]any, error) {
	if g.Scope.Error != nil {
		return nil, g.Scope.Error
	}
	if g.Scope.Data != scopeOrganization {
		return nil, nil
	}
	if g.Visibility.Error != nil {
		return nil, g.Visibility.Error
	}
	if g.Visibility.Data != "selected" {
		return nil, nil
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}

	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	opts := &github.ListOptions{PerPage: paginationPerPage}
	var all []*github.Repository
	for {
		page, resp, err := conn.Client().Actions.ListSelectedReposForOrgVariable(conn.Context(), g.orgLogin, g.Name.Data, opts)
		if err != nil {
			return handleActionsListErr(err, "selected repositories for variable")
		}
		all = append(all, page.Repositories...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return reposToMql(g.MqlRuntime, all)
}

// repoOwner returns the repository's owner resource. The owner is legitimately
// null on fork entries and on repositories built from a partial API response
// (see newMqlGithubRepository and reposToMql), so callers must never
// dereference g.Owner.Data without going through this helper — doing so panics
// the whole GetData call.
func repoOwner(g *mqlGithubRepository) (*mqlGithubUser, error) {
	if g.Owner.Error != nil {
		return nil, g.Owner.Error
	}
	if g.Owner.Data == nil {
		name := ""
		if g.Name.Error == nil {
			name = g.Name.Data
		}
		return nil, fmt.Errorf("repository %q has no owner information available", name)
	}
	return g.Owner.Data, nil
}

func repoOwnerAndName(g *mqlGithubRepository) (string, string, error) {
	if g.Name.Error != nil {
		return "", "", g.Name.Error
	}
	owner, err := repoOwner(g)
	if err != nil {
		return "", "", err
	}
	if owner.Login.Error != nil {
		return "", "", owner.Login.Error
	}
	return owner.Login.Data, g.Name.Data, nil
}

// reposToMql turns a slice of go-github Repository into MQL github.repository resources.
// The data here is intentionally minimal — full repo data is fetched lazily when other
// fields are accessed.
func reposToMql(runtime *plugin.Runtime, repos []*github.Repository) ([]any, error) {
	res := make([]any, 0, len(repos))
	for _, r := range repos {
		args := map[string]*llx.RawData{
			"id":       llx.IntDataDefault(r.ID, 0),
			"name":     llx.StringDataPtr(r.Name),
			"fullName": llx.StringDataPtr(r.FullName),
		}
		repo, err := NewResource(runtime, "github.repository", args)
		if err != nil {
			return nil, err
		}
		res = append(res, repo)
	}
	return res, nil
}

// handleActionsListErr maps inaccessible GitHub Actions endpoints (404/403) to nil
// results so a query against an unauthorized scope (no admin:org / admin:repo)
// doesn't fail the whole run. Uses the typed *github.ErrorResponse via the shared
// isAccessDeniedOrNotFound helper rather than fragile string matching.
func handleActionsListErr(err error, what string) ([]any, error) {
	if isAccessDeniedOrNotFound(err) {
		log.Debug().Str("scope", what).Err(err).Msg("not accessible with current credentials")
		return nil, nil
	}
	return nil, err
}
