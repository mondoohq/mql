// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"sync"

	"github.com/google/go-github/v93/github"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/github/connection"
	"go.mondoo.com/mql/types"
)

// Code security configurations are how an organization rolls GitHub Advanced
// Security, Dependabot, secret scanning and code scanning out to its
// repositories: a configuration is attached to repositories and sets each of
// their features.

type mqlGithubCodeSecurityConfigurationInternal struct {
	cacheOrgLogin  string
	cacheReviewers []*github.BypassReviewer
}

func (g *mqlGithubCodeSecurityConfiguration) id() (string, error) {
	return g.__id, nil
}

func (g *mqlGithubCodeSecurityConfigurationRepository) id() (string, error) {
	return g.__id, nil
}

// codeSecurityConfigurationID keys a configuration by the organization it is
// read through. The configurations GitHub provides carry the same id in every
// organization, but their attachments and defaults differ per organization.
func codeSecurityConfigurationID(orgLogin string, id int64) string {
	return "github.codeSecurityConfiguration/" + orgLogin + "/" + strconv.FormatInt(id, 10)
}

// bypassReviewersToDicts reports the delegated bypass reviewers as dicts. Nil
// options, the shape of a configuration without delegated bypass, report no
// reviewers.
func bypassReviewersToDicts(opts *github.SecretScanningDelegatedBypassOptions) []any {
	res := []any{}
	if opts == nil {
		return res
	}
	for _, r := range opts.Reviewers {
		if r == nil {
			continue
		}
		res = append(res, map[string]any{
			"reviewerId":   r.ReviewerID,
			"reviewerType": r.ReviewerType,
		})
	}
	return res
}

func newMqlCodeSecurityConfiguration(runtime *plugin.Runtime, orgLogin string, c *github.CodeSecurityConfiguration) (*mqlGithubCodeSecurityConfiguration, error) {
	var runnerType, runnerLabel *string
	if o := c.CodeScanningDefaultSetupOptions; o != nil {
		runnerType = &o.RunnerType
		runnerLabel = o.RunnerLabel
	}
	var allowAdvanced, labeledRunners *bool
	if o := c.CodeScanningOptions; o != nil {
		allowAdvanced = o.AllowAdvanced
	}
	if o := c.DependencyGraphAutosubmitActionOptions; o != nil {
		labeledRunners = o.LabeledRunners
	}
	var reviewers []*github.BypassReviewer
	if c.SecretScanningDelegatedBypassOptions != nil {
		reviewers = c.SecretScanningDelegatedBypassOptions.Reviewers
	}

	r, err := CreateResource(runtime, "github.codeSecurityConfiguration", map[string]*llx.RawData{
		"__id":                            llx.StringData(codeSecurityConfigurationID(orgLogin, c.GetID())),
		"id":                              llx.IntDataPtr(c.ID),
		"name":                            llx.StringData(c.Name),
		"description":                     llx.StringData(c.Description),
		"targetType":                      llx.StringDataPtr(c.TargetType),
		"enforcement":                     llx.StringDataPtr(c.Enforcement),
		"advancedSecurity":                llx.StringDataPtr(c.AdvancedSecurity),
		"codeSecurity":                    llx.StringDataPtr(c.CodeSecurity),
		"secretProtection":                llx.StringDataPtr(c.SecretProtection),
		"dependencyGraph":                 llx.StringDataPtr(c.DependencyGraph),
		"dependencyGraphAutosubmitAction": llx.StringDataPtr(c.DependencyGraphAutosubmitAction),
		"dependencyGraphAutosubmitActionLabeledRunners": llx.BoolDataPtr(labeledRunners),
		"dependabotAlerts":                       llx.StringDataPtr(c.DependabotAlerts),
		"dependabotSecurityUpdates":              llx.StringDataPtr(c.DependabotSecurityUpdates),
		"dependabotDelegatedAlertDismissal":      llx.StringDataPtr(c.DependabotDelegatedAlertDismissal),
		"codeScanningDefaultSetup":               llx.StringDataPtr(c.CodeScanningDefaultSetup),
		"codeScanningDefaultSetupRunnerType":     llx.StringDataPtr(runnerType),
		"codeScanningDefaultSetupRunnerLabel":    llx.StringDataPtr(runnerLabel),
		"codeScanningAllowAdvanced":              llx.BoolDataPtr(allowAdvanced),
		"codeScanningDelegatedAlertDismissal":    llx.StringDataPtr(c.CodeScanningDelegatedAlertDismissal),
		"secretScanning":                         llx.StringDataPtr(c.SecretScanning),
		"secretScanningPushProtection":           llx.StringDataPtr(c.SecretScanningPushProtection),
		"secretScanningDelegatedBypass":          llx.StringDataPtr(c.SecretScanningDelegatedBypass),
		"secretScanningDelegatedBypassReviewers": llx.ArrayData(bypassReviewersToDicts(c.SecretScanningDelegatedBypassOptions), types.Dict),
		"secretScanningValidityChecks":           llx.StringDataPtr(c.SecretScanningValidityChecks),
		"secretScanningNonProviderPatterns":      llx.StringDataPtr(c.SecretScanningNonProviderPatterns),
		"secretScanningGenericSecrets":           llx.StringDataPtr(c.SecretScanningGenericSecrets),
		"secretScanningDelegatedAlertDismissal":  llx.StringDataPtr(c.SecretScanningDelegatedAlertDismissal),
		"secretScanningExtendedMetadata":         llx.StringDataPtr(c.SecretScanningExtendedMetadata),
		"privateVulnerabilityReporting":          llx.StringDataPtr(c.PrivateVulnerabilityReporting),
		"createdAt":                              llx.TimeDataPtr(githubTime(c.CreatedAt)),
		"updatedAt":                              llx.TimeDataPtr(githubTime(c.UpdatedAt)),
	})
	if err != nil {
		return nil, err
	}
	res := r.(*mqlGithubCodeSecurityConfiguration)
	res.cacheOrgLogin = orgLogin
	res.cacheReviewers = reviewers
	return res, nil
}

func (g *mqlGithubOrganization) codeSecurityConfigurations() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	all, err := collectCursorPages(func(after string) ([]*github.CodeSecurityConfiguration, *github.Response, error) {
		return conn.Client().Organizations.ListCodeSecurityConfigurations(conn.Context(), orgLogin,
			&github.ListOrgCodeSecurityConfigurationOptions{PerPage: paginationPerPage, After: after})
	})
	if err != nil {
		if err := classifyReadErr(err, "code security configurations", orgLogin); err != nil {
			return nil, err
		}
		g.CodeSecurityConfigurations.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := make([]any, 0, len(all))
	for _, c := range all {
		if c == nil {
			continue
		}
		r, err := newMqlCodeSecurityConfiguration(g.MqlRuntime, orgLogin, c)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// defaultForNewRepos maps configuration ids to the repositories each one is
// the default for. A configuration missing from the map is the default for
// none.
func defaultsForNewRepos(defaults []*github.CodeSecurityConfigurationWithDefaultForNewRepos) map[int64]string {
	res := make(map[int64]string, len(defaults))
	for _, d := range defaults {
		if d == nil || d.Configuration == nil || d.Configuration.ID == nil || d.DefaultForNewRepos == nil {
			continue
		}
		res[*d.Configuration.ID] = *d.DefaultForNewRepos
	}
	return res
}

func (g *mqlGithubCodeSecurityConfiguration) defaultForNewRepos() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	orgLogin := g.cacheOrgLogin
	defaults, err := memoized(g.MqlRuntime, "code-security-defaults-"+orgLogin, func() (any, error) {
		list, _, err := conn.Client().Organizations.ListDefaultCodeSecurityConfigurations(conn.Context(), orgLogin)
		if err != nil {
			return nil, err
		}
		return defaultsForNewRepos(list), nil
	})
	if err != nil {
		if err := classifyReadErr(err, "default code security configurations", orgLogin); err != nil {
			return "", err
		}
		g.DefaultForNewRepos.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	if v, ok := defaults.(map[int64]string)[g.Id.Data]; ok {
		return v, nil
	}
	return "none", nil
}

func (g *mqlGithubCodeSecurityConfiguration) repositories() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	orgLogin := g.cacheOrgLogin
	configID := g.Id.Data

	all, err := collectCursorPages(func(after string) ([]*github.RepositoryAttachment, *github.Response, error) {
		return conn.Client().Organizations.ListCodeSecurityConfigurationRepositories(conn.Context(), orgLogin, configID,
			&github.ListCodeSecurityConfigurationRepositoriesOptions{PerPage: paginationPerPage, After: after})
	})
	if err != nil {
		if err := classifyReadErr(err, "code security configuration repositories", orgLogin); err != nil {
			return nil, err
		}
		g.Repositories.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := make([]any, 0, len(all))
	for _, a := range all {
		if a == nil || a.Repository == nil || a.Repository.ID == nil {
			continue
		}
		repo, err := newMqlGithubRepository(g.MqlRuntime, a.Repository)
		if err != nil {
			return nil, err
		}
		r, err := CreateResource(g.MqlRuntime, "github.codeSecurityConfigurationRepository", map[string]*llx.RawData{
			"__id":       llx.StringData(g.__id + "/" + strconv.FormatInt(*a.Repository.ID, 10)),
			"repository": llx.ResourceData(repo, repo.MqlName()),
			"status":     llx.StringDataPtr(a.Status),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// secretScanningDelegatedBypassTeams resolves the TEAM reviewers against the
// organization's team list, which is read once and shared.
func (g *mqlGithubCodeSecurityConfiguration) secretScanningDelegatedBypassTeams() ([]any, error) {
	ids := map[int64]struct{}{}
	for _, r := range g.cacheReviewers {
		if r != nil && r.ReviewerType == "TEAM" {
			ids[r.ReviewerID] = struct{}{}
		}
	}
	res := []any{}
	if len(ids) == 0 {
		return res, nil
	}
	orgData := organizationResource(g.MqlRuntime, g.cacheOrgLogin)
	org, ok := orgData.Value.(*mqlGithubOrganization)
	if !ok || org == nil {
		g.SecretScanningDelegatedBypassTeams.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	teams := org.GetTeams()
	if teams.Error != nil {
		return nil, teams.Error
	}
	if teams.State&plugin.StateIsNull != 0 {
		g.SecretScanningDelegatedBypassTeams.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	for _, t := range teams.Data {
		team, ok := t.(*mqlGithubTeam)
		if !ok || team.Id.Error != nil {
			continue
		}
		if _, want := ids[team.Id.Data]; want {
			res = append(res, team)
		}
	}
	return res, nil
}

// ---------- Repository attachment ----------

type repoCodeSecurityConfig struct {
	once sync.Once
	data *github.RepositoryCodeSecurityConfiguration
	err  error
}

// repositoryCodeSecurityConfiguration reads the repository's attachment once
// for both fields that report it. A nil result with no error means the value
// is unknown or there is no attachment.
func (g *mqlGithubRepository) repositoryCodeSecurityConfiguration() (*github.RepositoryCodeSecurityConfiguration, error) {
	g.codeSecurityConfig.once.Do(func() {
		owner, repo, err := repoOwnerAndName(g)
		if err != nil {
			g.codeSecurityConfig.err = err
			return
		}
		conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
		data, _, err := conn.Client().Organizations.GetCodeSecurityConfigurationForRepository(conn.Context(), owner, repo)
		if err != nil {
			g.codeSecurityConfig.err = classifyReadErr(err, "repository code security configuration", owner+"/"+repo)
			return
		}
		g.codeSecurityConfig.data = data
	})
	return g.codeSecurityConfig.data, g.codeSecurityConfig.err
}

func (g *mqlGithubRepository) codeSecurityConfiguration() (*mqlGithubCodeSecurityConfiguration, error) {
	data, err := g.repositoryCodeSecurityConfiguration()
	if err != nil {
		return nil, err
	}
	if data == nil || data.Configuration == nil || data.Configuration.ID == nil {
		g.CodeSecurityConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	owner, _, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}
	return newMqlCodeSecurityConfiguration(g.MqlRuntime, owner, data.Configuration)
}

func (g *mqlGithubRepository) codeSecurityConfigurationState() (string, error) {
	data, err := g.repositoryCodeSecurityConfiguration()
	if err != nil {
		return "", err
	}
	if data == nil || data.State == nil {
		g.CodeSecurityConfigurationState.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *data.State, nil
}
