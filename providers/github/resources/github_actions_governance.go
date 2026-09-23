// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"

	"github.com/google/go-github/v92/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/github/connection"
	"go.mondoo.com/mql/types"
)

// ---------- Self-hosted runner groups ----------

// cacheOrgLogin carries the organization to the group's own lookups. It is
// assigned after CreateResource returns, which is soon enough for those, but
// too late for the cache key: see runnerGroupID.
type mqlGithubOrganizationRunnerGroupInternal struct {
	cacheOrgLogin string
}

// runnerGroupID keys a runner group by the organization that defines it.
// Groups are numbered per organization, so the numeric id alone collides
// across organizations. The key is passed to CreateResource explicitly,
// because the generated constructor computes a missing __id from inside
// CreateResource, before cacheOrgLogin has been assigned.
func runnerGroupID(orgLogin string, id int64) string {
	return "github.organization.runnerGroup/" + orgLogin + "/" + strconv.FormatInt(id, 10)
}

func (g *mqlGithubOrganizationRunnerGroup) id() (string, error) {
	return g.__id, nil
}

func (g *mqlGithubOrganization) runnerGroups() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	listOpts := &github.ListOrgRunnerGroupOptions{
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
	}
	var allGroups []*github.RunnerGroup
	for {
		groups, resp, err := conn.Client().Actions.ListOrganizationRunnerGroups(conn.Context(), orgLogin, listOpts)
		if err != nil {
			if isAccessDeniedOrNotFound(err) {
				log.Debug().Err(err).Str("org", orgLogin).
					Msg("runner groups are not accessible (requires organization admin access)")
				return nil, nil
			}
			return nil, err
		}
		allGroups = append(allGroups, groups.RunnerGroups...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := []any{}
	for _, group := range allGroups {
		r, err := CreateResource(g.MqlRuntime, "github.organization.runnerGroup", map[string]*llx.RawData{
			"__id":                         llx.StringData(runnerGroupID(orgLogin, group.GetID())),
			"id":                           llx.IntDataDefault(group.ID, 0),
			"name":                         llx.StringDataPtr(group.Name),
			"visibility":                   llx.StringDataPtr(group.Visibility),
			"isDefault":                    llx.BoolDataPtr(group.Default),
			"inherited":                    llx.BoolDataPtr(group.Inherited),
			"allowsPublicRepositories":     llx.BoolDataPtr(group.AllowsPublicRepositories),
			"restrictedToWorkflows":        llx.BoolDataPtr(group.RestrictedToWorkflows),
			"selectedWorkflows":            llx.ArrayData(convert.SliceAnyToInterface(group.SelectedWorkflows), types.String),
			"workflowRestrictionsReadOnly": llx.BoolDataPtr(group.WorkflowRestrictionsReadOnly),
			"networkConfigurationId":       llx.StringData(group.GetNetworkConfigurationID()),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlGithubOrganizationRunnerGroup).cacheOrgLogin = orgLogin
		res = append(res, r)
	}

	return res, nil
}

// selectedRepositories returns the repositories allowed to use the group. It is
// empty for a group whose visibility is not "selected", where every repository
// the visibility covers may use it.
func (g *mqlGithubOrganizationRunnerGroup) selectedRepositories() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	groupID := g.Id.Data

	listOpts := &github.ListOptions{PerPage: paginationPerPage}
	res := []any{}
	for {
		repos, resp, err := conn.Client().Actions.ListRepositoryAccessRunnerGroup(conn.Context(), g.cacheOrgLogin, groupID, listOpts)
		if err != nil {
			if isAccessDeniedOrNotFound(err) {
				log.Debug().Err(err).Str("org", g.cacheOrgLogin).Int64("group", groupID).
					Msg("runner group repository access is not accessible")
				return nil, nil
			}
			return nil, err
		}
		for _, repo := range repos.Repositories {
			r, err := NewResource(g.MqlRuntime, "github.repository", map[string]*llx.RawData{
				"id":       llx.IntDataDefault(repo.ID, 0),
				"name":     llx.StringDataPtr(repo.Name),
				"fullName": llx.StringDataPtr(repo.FullName),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	return res, nil
}

// runners returns the self-hosted runners registered in the group. They are
// keyed by the organization rather than the group so a runner reached through
// its group and through the organization resolves to the same resource.
func (g *mqlGithubOrganizationRunnerGroup) runners() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}

	path := fmt.Sprintf("orgs/%s/actions/runner-groups/%d/runners", g.cacheOrgLogin, g.Id.Data)
	runners, err := listRunnersRaw(conn.Context(), conn.Client(), path)
	if err != nil {
		if isAccessDeniedOrNotFound(err) {
			log.Debug().Err(err).Str("org", g.cacheOrgLogin).Int64("group", g.Id.Data).
				Msg("runner group runners are not accessible")
			return nil, nil
		}
		return nil, err
	}

	return runnersToMql(g.MqlRuntime, "orgs/"+g.cacheOrgLogin, runners)
}

// ---------- Organization rulesets ----------

// rulesets returns the rulesets the organization applies across its
// repositories, which are enforced in addition to any ruleset a repository
// defines for itself.
func (g *mqlGithubOrganization) rulesets() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	listOpts := &github.ListOptions{PerPage: paginationPerPage}
	var allRulesets []*github.RepositoryRuleset
	for {
		rulesets, resp, err := conn.Client().Organizations.ListAllRepositoryRulesets(conn.Context(), orgLogin, listOpts)
		if err != nil {
			if isAccessDeniedOrNotFound(err) {
				log.Debug().Err(err).Str("org", orgLogin).
					Msg("organization rulesets are not accessible (requires organization admin access)")
				return nil, nil
			}
			return nil, err
		}
		allRulesets = append(allRulesets, rulesets...)
		if resp.NextPage == 0 {
			break
		}
		listOpts.Page = resp.NextPage
	}

	res := make([]any, 0, len(allRulesets))
	for _, rs := range allRulesets {
		r, err := newMqlRepositoryRuleset(g.MqlRuntime, orgLogin, rs)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// newMqlRepositoryRuleset converts a ruleset to its MQL resource. scope keys the
// resource by where the ruleset is defined, so an organization ruleset and a
// repository ruleset that share an id stay distinct.
func newMqlRepositoryRuleset(runtime *plugin.Runtime, scope string, rs *github.RepositoryRuleset) (plugin.Resource, error) {
	bypassActors := make([]any, 0, len(rs.BypassActors))
	for _, ba := range rs.BypassActors {
		d, err := convert.JsonToDict(ba)
		if err != nil {
			return nil, err
		}
		bypassActors = append(bypassActors, d)
	}

	conditions, err := convert.JsonToDict(rs.Conditions)
	if err != nil {
		return nil, err
	}

	rules, err := convert.JsonToDictSlice(rs.Rules)
	if err != nil {
		return nil, err
	}

	var target, sourceType string
	if rs.Target != nil {
		target = string(*rs.Target)
	}
	if rs.SourceType != nil {
		sourceType = string(*rs.SourceType)
	}

	rulesetID := strconv.FormatInt(rs.GetID(), 10)
	return CreateResource(runtime, "github.repositoryRuleset", map[string]*llx.RawData{
		"__id":         llx.StringData("github.repositoryRuleset/" + scope + "/" + rulesetID),
		"id":           llx.IntDataPtr(rs.ID),
		"name":         llx.StringData(rs.Name),
		"target":       llx.StringData(target),
		"sourceType":   llx.StringData(sourceType),
		"source":       llx.StringData(rs.Source),
		"enforcement":  llx.StringData(string(rs.Enforcement)),
		"bypassActors": llx.ArrayData(bypassActors, types.Dict),
		"conditions":   llx.MapData(conditions, types.Any),
		"rules":        llx.ArrayData(rules, types.Dict),
		"createdAt":    llx.TimeDataPtr(githubTimestamp(rs.CreatedAt)),
		"updatedAt":    llx.TimeDataPtr(githubTimestamp(rs.UpdatedAt)),
	})
}

// ---------- OIDC subject claim customization ----------

// oidcSubjectClaimKeys returns the claims the organization adds to the subject
// of the OIDC tokens its workflows present to cloud providers.
func (g *mqlGithubOrganization) oidcSubjectClaimKeys() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	orgLogin := g.Login.Data

	template, _, err := conn.Client().Actions.GetOrgOIDCSubjectClaimCustomTemplate(conn.Context(), orgLogin)
	if err != nil {
		if isAccessDeniedOrNotFound(err) {
			log.Debug().Err(err).Str("org", orgLogin).
				Msg("OIDC subject claim template is not accessible (requires organization admin access)")
			return nil, nil
		}
		return nil, err
	}
	return oidcClaimKeys(template), nil
}

// oidcSubjectClaimKeys returns the claims the repository adds to the subject of
// the OIDC tokens its workflows present to cloud providers.
func (g *mqlGithubRepository) oidcSubjectClaimKeys() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	template, _, err := conn.Client().Actions.GetRepoOIDCSubjectClaimCustomTemplate(conn.Context(), ownerLogin, repoName)
	if err != nil {
		if isAccessDeniedOrNotFound(err) {
			log.Debug().Err(err).Str("repo", ownerLogin+"/"+repoName).
				Msg("OIDC subject claim template is not accessible (requires repository admin access)")
			return nil, nil
		}
		return nil, err
	}
	return oidcClaimKeys(template), nil
}

// oidcClaimKeys returns the customized subject claims, or nil when the default
// subject format is in use. An empty list would read as "the subject carries no
// claims", where the default format in fact carries GitHub's own.
func oidcClaimKeys(template *github.OIDCSubjectClaimCustomTemplate) []any {
	if template == nil || template.GetUseDefault() || len(template.IncludeClaimKeys) == 0 {
		return nil
	}
	return convert.SliceAnyToInterface(template.IncludeClaimKeys)
}
