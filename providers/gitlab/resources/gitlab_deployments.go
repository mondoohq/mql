// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gitlab/connection"
	"go.mondoo.com/mql/types"

	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
)

// This file models where a project deploys to: its environments, the latest
// deployment to each, and the protected environments a group sets for a
// deployment tier across all of its projects. Environment and deployment ids
// are keyed per project and protected environment names per group, since a
// name such as production repeats everywhere.

//
// Environments
//

// mqlGitlabProjectEnvironmentInternal keeps what the two typed accessors
// resolve on demand: the agent the environment deploys through and the
// project that holds that agent's configuration.
type mqlGitlabProjectEnvironmentInternal struct {
	project             *mqlGitlabProject
	cacheAgentID        int64
	cacheAgentProjectID int64
}

// environments lists the project's deployment environments.
func (p *mqlGitlabProject) environments() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := p.Id.Data

	all, err := collectPages(func(page int64) ([]*gitlab.Environment, *gitlab.Response, error) {
		return conn.Client().Environments.ListEnvironments(projectID, &gitlab.ListEnvironmentsOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
	})
	if err != nil {
		if err = gatedError(err); err != nil {
			return nil, err
		}
		return []any{}, nil
	}

	res := make([]any, 0, len(all))
	for _, env := range all {
		if env == nil {
			continue
		}
		mqlEnv, err := CreateResource(p.MqlRuntime, "gitlab.project.environment", map[string]*llx.RawData{
			"__id":                llx.StringData(projectScopedID("gitlab.project.environment", projectID, strconv.FormatInt(env.ID, 10))),
			"id":                  llx.IntData(env.ID),
			"name":                llx.StringData(env.Name),
			"slug":                llx.StringData(env.Slug),
			"description":         llx.StringData(env.Description),
			"state":               llx.StringData(env.State),
			"tier":                llx.StringData(env.Tier),
			"externalUrl":         llx.StringData(env.ExternalURL),
			"kubernetesNamespace": llx.StringData(env.KubernetesNamespace),
			"fluxResourcePath":    llx.StringData(env.FluxResourcePath),
			"autoStopAt":          llx.TimeDataPtr(env.AutoStopAt),
			"autoStopSetting":     llx.StringData(env.AutoStopSetting),
			"createdAt":           llx.TimeDataPtr(env.CreatedAt),
			"updatedAt":           llx.TimeDataPtr(env.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		internal := mqlEnv.(*mqlGitlabProjectEnvironment)
		internal.project = p
		if env.ClusterAgent != nil {
			internal.cacheAgentID = env.ClusterAgent.ID
			internal.cacheAgentProjectID = env.ClusterAgent.ConfigProject.ID
		}
		res = append(res, mqlEnv)
	}
	return res, nil
}

// clusterAgent resolves the environment's agent through the agent list of the
// project holding its configuration, which is usually this project.
func (e *mqlGitlabProjectEnvironment) clusterAgent() (*mqlGitlabProjectClusterAgent, error) {
	if e.cacheAgentID <= 0 || e.cacheAgentProjectID <= 0 {
		e.ClusterAgent.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	configProject := e.project
	if configProject == nil || configProject.Id.Data != e.cacheAgentProjectID {
		res, err := NewResource(e.MqlRuntime, "gitlab.project", map[string]*llx.RawData{
			"id": llx.IntData(e.cacheAgentProjectID),
		})
		if err != nil {
			return nil, err
		}
		configProject = res.(*mqlGitlabProject)
	}

	agents := configProject.GetClusterAgents()
	if agents.Error != nil {
		return nil, agents.Error
	}
	for _, a := range agents.Data {
		agent, ok := a.(*mqlGitlabProjectClusterAgent)
		if ok && agent.Id.Data == e.cacheAgentID {
			return agent, nil
		}
	}
	e.ClusterAgent.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// latestDeployment reads the most recent deployment to the environment. The
// environment listing does not include it, so this costs one request per
// environment and is only made when queried.
func (e *mqlGitlabProjectEnvironment) latestDeployment() (*mqlGitlabProjectDeployment, error) {
	if e.project == nil {
		e.LatestDeployment.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := e.MqlRuntime.Connection.(*connection.GitLabConnection)
	projectID := e.project.Id.Data
	name := e.Name.Data
	orderBy := "id"
	sort := "desc"

	deployments, _, err := conn.Client().Deployments.ListProjectDeployments(projectID, &gitlab.ListProjectDeploymentsOptions{
		ListOptions: gitlab.ListOptions{Page: 1, PerPage: 1},
		Environment: &name,
		OrderBy:     &orderBy,
		Sort:        &sort,
	})
	if err != nil {
		if err = gatedError(err); err != nil {
			return nil, err
		}
		deployments = nil
	}
	if len(deployments) == 0 || deployments[0] == nil {
		e.LatestDeployment.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlDeployment(e.MqlRuntime, projectID, deployments[0])
}

type mqlGitlabProjectDeploymentInternal struct {
	cacheUserID int64
}

func newMqlDeployment(runtime *plugin.Runtime, projectID int64, d *gitlab.Deployment) (*mqlGitlabProjectDeployment, error) {
	res, err := CreateResource(runtime, "gitlab.project.deployment", map[string]*llx.RawData{
		"__id":                 llx.StringData(projectScopedID("gitlab.project.deployment", projectID, strconv.FormatInt(d.ID, 10))),
		"id":                   llx.IntData(d.ID),
		"internalId":           llx.IntData(d.IID),
		"ref":                  llx.StringData(d.Ref),
		"sha":                  llx.StringData(d.SHA),
		"status":               llx.StringData(d.Status),
		"createdAt":            llx.TimeDataPtr(d.CreatedAt),
		"updatedAt":            llx.TimeDataPtr(d.UpdatedAt),
		"pendingApprovalCount": llx.IntDataPtr(d.PendingApprovalCount),
	})
	if err != nil {
		return nil, err
	}
	deployment := res.(*mqlGitlabProjectDeployment)
	if d.User != nil {
		deployment.cacheUserID = d.User.ID
	}
	return deployment, nil
}

func (d *mqlGitlabProjectDeployment) user() (*mqlGitlabUser, error) {
	if d.cacheUserID <= 0 {
		d.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return gitlabUserRef(d.MqlRuntime, d.cacheUserID)
}

//
// Group protected environments
//

// protectedEnvironments lists the deployment gates the group sets per
// deployment tier. Premium only; other tiers answer 404 and read as an empty
// list.
func (g *mqlGitlabGroup) protectedEnvironments() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GitLabConnection)
	groupID := g.Id.Data

	all, err := collectPages(func(page int64) ([]*gitlab.GroupProtectedEnvironment, *gitlab.Response, error) {
		return conn.Client().GroupProtectedEnvironments.ListGroupProtectedEnvironments(groupID, &gitlab.ListGroupProtectedEnvironmentsOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: gitlabPerPage},
		})
	})
	if err != nil {
		if err = gatedError(err); err != nil {
			return nil, err
		}
		return []any{}, nil
	}

	res := make([]any, 0, len(all))
	for _, env := range all {
		if env == nil {
			continue
		}
		mqlEnv, err := CreateResource(g.MqlRuntime, "gitlab.group.protectedEnvironment", map[string]*llx.RawData{
			"__id":                  llx.StringData(groupScopedID("gitlab.group.protectedEnvironment", groupID, env.Name)),
			"name":                  llx.StringData(env.Name),
			"requiredApprovalCount": llx.IntData(env.RequiredApprovalCount),
			"deployAccessLevels":    llx.ArrayData(envDeployAccessLevelsToDicts(groupEnvAccessLevels(env.DeployAccessLevels)), types.Dict),
			"approvalRules":         llx.ArrayData(envApprovalRulesToDicts(groupEnvApprovalRules(env.ApprovalRules)), types.Dict),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlEnv)
	}
	return res, nil
}

// groupEnvAccessLevels converts the group-scope access levels to the project
// type they mirror field for field, so both scopes share one dict shape.
func groupEnvAccessLevels(in []*gitlab.GroupEnvironmentAccessDescription) []*gitlab.EnvironmentAccessDescription {
	out := make([]*gitlab.EnvironmentAccessDescription, 0, len(in))
	for _, d := range in {
		out = append(out, (*gitlab.EnvironmentAccessDescription)(d))
	}
	return out
}

// groupEnvApprovalRules is the approval rule counterpart of groupEnvAccessLevels.
func groupEnvApprovalRules(in []*gitlab.GroupEnvironmentApprovalRule) []*gitlab.EnvironmentApprovalRule {
	out := make([]*gitlab.EnvironmentApprovalRule, 0, len(in))
	for _, r := range in {
		out = append(out, (*gitlab.EnvironmentApprovalRule)(r))
	}
	return out
}
