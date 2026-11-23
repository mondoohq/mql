// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"sync"

	"github.com/google/go-github/v93/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/github/connection"
)

// Each Actions setting below lives behind its own endpoint, and several fields
// share one endpoint, so every endpoint is read at most once per settings
// resource and the fields project from the cached answer.

// actionsSetting caches one read of an Actions settings endpoint. A nil value
// with a nil error means the setting is unknown: refused, not applicable here,
// or not reported, which the fields render as null.
type actionsSetting[T any] struct {
	once sync.Once
	val  *T
	err  error
}

func (c *actionsSetting[T]) get(what, scope string, fetch func() (*T, error)) (*T, error) {
	c.once.Do(func() {
		v, err := fetch()
		if err != nil {
			c.err = classifyActionsSettingErr(err, what, scope)
			return
		}
		c.val = v
	})
	return c.val, c.err
}

// classifyActionsSettingErr maps an answer that leaves a setting unknown to
// nil, so the field reads null: 403 is a refused read, 404 and 409 mean the
// setting does not exist for this scope, and 422 is GitHub declining to apply
// it, as the private-repository fork settings do for a public repository.
// Anything else, including a transport failure, stays an error rather than
// turning into a posture verdict.
func classifyActionsSettingErr(err error, what, scope string) error {
	switch {
	case githubForbidden(err):
		log.Warn().Err(err).Str("scope", scope).Str("setting", what).
			Msg("permission denied reading an Actions setting; reporting it as unknown")
		return nil
	case githubNotAvailable(err), githubResponseStatus(err) == http.StatusUnprocessableEntity:
		log.Debug().Err(err).Str("scope", scope).Str("setting", what).
			Msg("the Actions setting does not apply to this scope")
		return nil
	}
	return err
}

// optionalString renders a string that may be absent or empty as null.
func optionalString(v *string, field *plugin.TValue[string]) (string, error) {
	if v == nil || *v == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *v, nil
}

// optionalInt renders an int that may be absent as null.
func optionalInt(v *int, field *plugin.TValue[int64]) (int64, error) {
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*v), nil
}

// forkPrBool projects one switch of the fork pull request workflow settings.
func forkPrBool(p *github.WorkflowsPermissions, pick func(*github.WorkflowsPermissions) *bool, field *plugin.TValue[bool]) (bool, error) {
	if p == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return allowlistBool(pick(p), field)
}

func approvalPolicy(p *github.ContributorApprovalPermissions) *string {
	if p == nil {
		return nil
	}
	return &p.ApprovalPolicy
}

func pickRunWorkflows(p *github.WorkflowsPermissions) *bool {
	return p.RunWorkflowsFromForkPullRequests
}
func pickWriteTokens(p *github.WorkflowsPermissions) *bool { return p.SendWriteTokensToWorkflows }
func pickSecrets(p *github.WorkflowsPermissions) *bool     { return p.SendSecretsAndVariables }
func pickRequireApproval(p *github.WorkflowsPermissions) *bool {
	return p.RequireApprovalForForkPRWorkflows
}

func retentionDays(p *github.ArtifactPeriod) *int {
	if p == nil {
		return nil
	}
	return p.Days
}

func retentionMaxDays(p *github.ArtifactPeriod) *int {
	if p == nil {
		return nil
	}
	return p.MaximumAllowedDays
}

// ---------- repository ----------

func (g *mqlGithubRepositoryActionsSettings) scope() string {
	return g.ownerLogin + "/" + g.repoName
}

func (g *mqlGithubRepositoryActionsSettings) contributorApproval() (*github.ContributorApprovalPermissions, error) {
	return g.contributorApprovalSetting.get("fork-pr-contributor-approval", g.scope(), func() (*github.ContributorApprovalPermissions, error) {
		conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
		p, _, err := conn.Client().Actions.GetForkPRContributorApprovalPermissions(conn.Context(), g.ownerLogin, g.repoName)
		return p, err
	})
}

func (g *mqlGithubRepositoryActionsSettings) forkPrWorkflows() (*github.WorkflowsPermissions, error) {
	return g.forkPrWorkflowsSetting.get("fork-pr-workflows-private-repos", g.scope(), func() (*github.WorkflowsPermissions, error) {
		conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
		p, _, err := conn.Client().Repositories.GetPrivateRepoForkPRWorkflowSettings(conn.Context(), g.ownerLogin, g.repoName)
		return p, err
	})
}

func (g *mqlGithubRepositoryActionsSettings) artifactRetention() (*github.ArtifactPeriod, error) {
	return g.retentionSetting.get("artifact-and-log-retention", g.scope(), func() (*github.ArtifactPeriod, error) {
		conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
		p, _, err := conn.Client().Repositories.GetArtifactAndLogRetentionPeriod(conn.Context(), g.ownerLogin, g.repoName)
		return p, err
	})
}

func (g *mqlGithubRepositoryActionsSettings) forkPrApprovalPolicy() (string, error) {
	p, err := g.contributorApproval()
	if err != nil {
		return "", err
	}
	return optionalString(approvalPolicy(p), &g.ForkPrApprovalPolicy)
}

func (g *mqlGithubRepositoryActionsSettings) forkPrWorkflowsEnabled() (bool, error) {
	p, err := g.forkPrWorkflows()
	if err != nil {
		return false, err
	}
	return forkPrBool(p, pickRunWorkflows, &g.ForkPrWorkflowsEnabled)
}

func (g *mqlGithubRepositoryActionsSettings) forkPrWriteTokens() (bool, error) {
	p, err := g.forkPrWorkflows()
	if err != nil {
		return false, err
	}
	return forkPrBool(p, pickWriteTokens, &g.ForkPrWriteTokens)
}

func (g *mqlGithubRepositoryActionsSettings) forkPrSecretsAndVariables() (bool, error) {
	p, err := g.forkPrWorkflows()
	if err != nil {
		return false, err
	}
	return forkPrBool(p, pickSecrets, &g.ForkPrSecretsAndVariables)
}

func (g *mqlGithubRepositoryActionsSettings) forkPrRequireApproval() (bool, error) {
	p, err := g.forkPrWorkflows()
	if err != nil {
		return false, err
	}
	return forkPrBool(p, pickRequireApproval, &g.ForkPrRequireApproval)
}

func (g *mqlGithubRepositoryActionsSettings) artifactRetentionDays() (int64, error) {
	p, err := g.artifactRetention()
	if err != nil {
		return 0, err
	}
	return optionalInt(retentionDays(p), &g.ArtifactRetentionDays)
}

func (g *mqlGithubRepositoryActionsSettings) artifactRetentionMaxDays() (int64, error) {
	p, err := g.artifactRetention()
	if err != nil {
		return 0, err
	}
	return optionalInt(retentionMaxDays(p), &g.ArtifactRetentionMaxDays)
}

// ---------- organization ----------

func (g *mqlGithubOrganizationActionsSettings) contributorApproval() (*github.ContributorApprovalPermissions, error) {
	return g.contributorApprovalSetting.get("fork-pr-contributor-approval", g.orgLogin, func() (*github.ContributorApprovalPermissions, error) {
		conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
		p, _, err := conn.Client().Actions.GetOrganizationForkPRContributorApprovalPermissions(conn.Context(), g.orgLogin)
		return p, err
	})
}

func (g *mqlGithubOrganizationActionsSettings) forkPrWorkflows() (*github.WorkflowsPermissions, error) {
	return g.forkPrWorkflowsSetting.get("fork-pr-workflows-private-repos", g.orgLogin, func() (*github.WorkflowsPermissions, error) {
		conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
		p, _, err := conn.Client().Actions.GetPrivateRepoForkPRWorkflowSettingsInOrganization(conn.Context(), g.orgLogin)
		return p, err
	})
}

func (g *mqlGithubOrganizationActionsSettings) artifactRetention() (*github.ArtifactPeriod, error) {
	return g.retentionSetting.get("artifact-and-log-retention", g.orgLogin, func() (*github.ArtifactPeriod, error) {
		conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
		p, _, err := conn.Client().Actions.GetArtifactAndLogRetentionPeriodInOrganization(conn.Context(), g.orgLogin)
		return p, err
	})
}

func (g *mqlGithubOrganizationActionsSettings) selfHostedRunners() (*github.SelfHostedRunnersSettingsOrganization, error) {
	return g.selfHostedRunnersSetting.get("self-hosted-runners", g.orgLogin, func() (*github.SelfHostedRunnersSettingsOrganization, error) {
		conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
		p, _, err := conn.Client().Actions.GetSelfHostedRunnersSettingsInOrganization(conn.Context(), g.orgLogin)
		return p, err
	})
}

func (g *mqlGithubOrganizationActionsSettings) forkPrApprovalPolicy() (string, error) {
	p, err := g.contributorApproval()
	if err != nil {
		return "", err
	}
	return optionalString(approvalPolicy(p), &g.ForkPrApprovalPolicy)
}

func (g *mqlGithubOrganizationActionsSettings) forkPrWorkflowsEnabled() (bool, error) {
	p, err := g.forkPrWorkflows()
	if err != nil {
		return false, err
	}
	return forkPrBool(p, pickRunWorkflows, &g.ForkPrWorkflowsEnabled)
}

func (g *mqlGithubOrganizationActionsSettings) forkPrWriteTokens() (bool, error) {
	p, err := g.forkPrWorkflows()
	if err != nil {
		return false, err
	}
	return forkPrBool(p, pickWriteTokens, &g.ForkPrWriteTokens)
}

func (g *mqlGithubOrganizationActionsSettings) forkPrSecretsAndVariables() (bool, error) {
	p, err := g.forkPrWorkflows()
	if err != nil {
		return false, err
	}
	return forkPrBool(p, pickSecrets, &g.ForkPrSecretsAndVariables)
}

func (g *mqlGithubOrganizationActionsSettings) forkPrRequireApproval() (bool, error) {
	p, err := g.forkPrWorkflows()
	if err != nil {
		return false, err
	}
	return forkPrBool(p, pickRequireApproval, &g.ForkPrRequireApproval)
}

func (g *mqlGithubOrganizationActionsSettings) artifactRetentionDays() (int64, error) {
	p, err := g.artifactRetention()
	if err != nil {
		return 0, err
	}
	return optionalInt(retentionDays(p), &g.ArtifactRetentionDays)
}

func (g *mqlGithubOrganizationActionsSettings) artifactRetentionMaxDays() (int64, error) {
	p, err := g.artifactRetention()
	if err != nil {
		return 0, err
	}
	return optionalInt(retentionMaxDays(p), &g.ArtifactRetentionMaxDays)
}

func (g *mqlGithubOrganizationActionsSettings) selfHostedRunnersEnabledRepositories() (string, error) {
	p, err := g.selfHostedRunners()
	if err != nil {
		return "", err
	}
	var v *string
	if p != nil {
		v = p.EnabledRepositories
	}
	return optionalString(v, &g.SelfHostedRunnersEnabledRepositories)
}

// selfHostedRunnersSelectedRepositories lists the repositories allowed to use
// self-hosted runners. GitHub keeps that list only while the setting is
// "selected"; for any other setting there is no list to report.
func (g *mqlGithubOrganizationActionsSettings) selfHostedRunnersSelectedRepositories() ([]any, error) {
	p, err := g.selfHostedRunners()
	if err != nil {
		return nil, err
	}
	if p == nil || p.GetEnabledRepositories() != "selected" {
		g.SelfHostedRunnersSelectedRepositories.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	listOpts := &github.ListOptions{PerPage: paginationPerPage}
	var all []*github.Repository
	for {
		page, resp, err := conn.Client().Actions.ListRepositoriesSelfHostedRunnersAllowedInOrganization(conn.Context(), g.orgLogin, listOpts)
		if err != nil {
			if cerr := classifyActionsSettingErr(err, "self-hosted-runners/repositories", g.orgLogin); cerr != nil {
				return nil, cerr
			}
			g.SelfHostedRunnersSelectedRepositories.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		if page != nil {
			all = append(all, page.Repositories...)
		}
		next := nextPage(listOpts.Page, resp)
		if next == 0 {
			break
		}
		listOpts.Page = next
	}
	return reposToMql(g.MqlRuntime, all)
}
