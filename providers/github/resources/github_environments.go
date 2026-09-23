// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/google/go-github/v92/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/github/connection"
	"go.mondoo.com/mql/types"
)

func (g *mqlGithubEnvironment) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "github.environment/" + strconv.FormatInt(g.Id.Data, 10), nil
}

func (g *mqlGithubEnvironmentProtectionRule) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "github.environmentProtectionRule/" + strconv.FormatInt(g.Id.Data, 10), nil
}

func (g *mqlGithubDeployment) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "github.deployment/" + strconv.FormatInt(g.Id.Data, 10), nil
}

func (g *mqlGithubDeploymentStatus) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return "github.deploymentStatus/" + strconv.FormatInt(g.Id.Data, 10), nil
}

// creatorData wraps an optional user resource for a CreateResource argument.
// Passing a nil *mqlGithubUser straight to llx.ResourceData stores a typed nil,
// which the runtime records as set-but-not-null and then dereferences when it
// serializes the field. NilData records a proper null instead.
func creatorData(user *mqlGithubUser) *llx.RawData {
	if user == nil {
		return llx.NilData
	}
	return llx.ResourceData(user, "github.user")
}

// environments returns the deployment environments for a repository.
func (g *mqlGithubRepository) environments() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	opts := &github.EnvironmentListOptions{
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
	}

	var allEnvironments []*github.Environment
	for {
		envResp, resp, err := conn.Client().Repositories.ListEnvironments(conn.Context(), ownerLogin, repoName, opts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			if strings.Contains(err.Error(), "403") {
				log.Debug().Msg("Deployment environments are not accessible for this repository")
				return nil, nil
			}
			return nil, err
		}
		allEnvironments = append(allEnvironments, envResp.Environments...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	var repoID int64
	if g.Id.Error == nil {
		repoID = g.Id.Data
	}

	return environmentsToMql(g.MqlRuntime, ownerLogin, repoName, repoID, allEnvironments)
}

// environmentsToMql converts a list of GitHub environments to MQL resources.
func environmentsToMql(runtime *plugin.Runtime, ownerLogin, repoName string, repoID int64, environments []*github.Environment) ([]any, error) {
	res := []any{}
	for _, env := range environments {
		// Extract branch policy fields
		var protectedBranches, customBranchPolicies bool
		if env.DeploymentBranchPolicy != nil {
			protectedBranches = convert.ToValue(env.DeploymentBranchPolicy.ProtectedBranches)
			customBranchPolicies = convert.ToValue(env.DeploymentBranchPolicy.CustomBranchPolicies)
		}

		// Convert protection rules
		protectionRules := []any{}
		for _, rule := range env.ProtectionRules {
			reviewers := []any{}
			for _, reviewer := range rule.Reviewers {
				reviewerDict := map[string]any{
					"type": convert.ToValue(reviewer.Type),
				}
				// Try to extract reviewer info based on type
				if reviewer.Reviewer != nil {
					if reviewerData, err := json.Marshal(reviewer.Reviewer); err == nil {
						var reviewerMap map[string]any
						if json.Unmarshal(reviewerData, &reviewerMap) == nil {
							for k, v := range reviewerMap {
								reviewerDict[k] = v
							}
						}
					}
				}
				reviewers = append(reviewers, reviewerDict)
			}

			ruleRes, err := CreateResource(runtime, "github.environmentProtectionRule", map[string]*llx.RawData{
				"id":                llx.IntDataDefault(rule.ID, 0),
				"type":              llx.StringDataPtr(rule.Type),
				"waitTimer":         llx.IntDataDefault(rule.WaitTimer, 0),
				"preventSelfReview": llx.BoolDataPtr(rule.PreventSelfReview),
				"reviewers":         llx.ArrayData(reviewers, types.Dict),
			})
			if err != nil {
				return nil, err
			}
			protectionRules = append(protectionRules, ruleRes)
		}

		envRes, err := CreateResource(runtime, "github.environment", map[string]*llx.RawData{
			"id":                   llx.IntDataDefault(env.ID, 0),
			"name":                 llx.StringDataPtr(env.Name),
			"url":                  llx.StringDataPtr(env.URL),
			"htmlUrl":              llx.StringDataPtr(env.HTMLURL),
			"waitTimer":            llx.IntDataDefault(env.WaitTimer, 0),
			"canAdminsBypass":      llx.BoolDataPtr(env.CanAdminsBypass),
			"createdAt":            llx.TimeDataPtr(githubTimestamp(env.CreatedAt)),
			"updatedAt":            llx.TimeDataPtr(githubTimestamp(env.UpdatedAt)),
			"protectedBranches":    llx.BoolData(protectedBranches),
			"customBranchPolicies": llx.BoolData(customBranchPolicies),
			"protectionRules":      llx.ArrayData(protectionRules, types.Resource("github.environmentProtectionRule")),
		})
		if err != nil {
			return nil, err
		}
		mqlEnv := envRes.(*mqlGithubEnvironment)
		mqlEnv.ownerLogin = ownerLogin
		mqlEnv.repoName = repoName
		mqlEnv.repoID = repoID
		res = append(res, mqlEnv)
	}

	return res, nil
}

type mqlGithubEnvironmentInternal struct {
	ownerLogin string
	repoName   string
	repoID     int64
}

// deployments returns the deployments for a repository.
func (g *mqlGithubRepository) deployments() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	ownerLogin, repoName, err := repoOwnerAndName(g)
	if err != nil {
		return nil, err
	}

	opts := &github.DeploymentsListOptions{
		ListOptions: github.ListOptions{PerPage: paginationPerPage},
	}

	var allDeployments []*github.Deployment
	for {
		deployments, resp, err := conn.Client().Repositories.ListDeployments(conn.Context(), ownerLogin, repoName, opts)
		if err != nil {
			if strings.Contains(err.Error(), "404") {
				return nil, nil
			}
			if strings.Contains(err.Error(), "403") {
				log.Debug().Msg("Deployments are not accessible for this repository")
				return nil, nil
			}
			return nil, err
		}
		allDeployments = append(allDeployments, deployments...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return deploymentsToMql(g.MqlRuntime, ownerLogin, repoName, allDeployments)
}

// deploymentsToMql converts a list of GitHub deployments to MQL resources.
func deploymentsToMql(runtime *plugin.Runtime, owner, repo string, deployments []*github.Deployment) ([]any, error) {
	res := []any{}
	for _, d := range deployments {
		var creator *mqlGithubUser
		if d.Creator != nil {
			creatorRes, err := NewResource(runtime, "github.user", map[string]*llx.RawData{
				"id":    llx.IntDataDefault(d.Creator.ID, 0),
				"login": llx.StringDataPtr(d.Creator.Login),
			})
			if err != nil {
				return nil, err
			}
			creator = creatorRes.(*mqlGithubUser)
		}

		// Create owner user resource
		ownerRes, err := NewResource(runtime, "github.user", map[string]*llx.RawData{
			"login": llx.StringData(owner),
		})
		if err != nil {
			return nil, err
		}

		// Convert payload to dict
		var payload map[string]any
		if d.Payload != nil {
			json.Unmarshal(d.Payload, &payload)
		}

		deploymentRes, err := CreateResource(runtime, "github.deployment", map[string]*llx.RawData{
			"id":          llx.IntDataDefault(d.ID, 0),
			"repoName":    llx.StringData(repo),
			"owner":       llx.ResourceData(ownerRes.(*mqlGithubUser), "github.user"),
			"sha":         llx.StringDataPtr(d.SHA),
			"ref":         llx.StringDataPtr(d.Ref),
			"task":        llx.StringDataPtr(d.Task),
			"environment": llx.StringDataPtr(d.Environment),
			"description": llx.StringDataPtr(d.Description),
			"creator":     creatorData(creator),
			"createdAt":   llx.TimeDataPtr(githubTimestamp(d.CreatedAt)),
			"updatedAt":   llx.TimeDataPtr(githubTimestamp(d.UpdatedAt)),
			"payload":     llx.MapData(payload, types.Any),
			"statusesUrl": llx.StringDataPtr(d.StatusesURL),
		})
		if err != nil {
			return nil, err
		}

		// Store owner/repo info for lazy loading of status
		deployment := deploymentRes.(*mqlGithubDeployment)
		deployment.ownerLogin = owner
		deployment.repoName = repo

		res = append(res, deployment)
	}

	return res, nil
}

type mqlGithubDeploymentInternal struct {
	ownerLogin string
	repoName   string
}

// latestStatus fetches the latest deployment status.
func (g *mqlGithubDeployment) latestStatus() (*mqlGithubDeploymentStatus, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)

	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	deploymentID := g.Id.Data

	// Get owner/repo from internal fields
	ownerLogin := g.ownerLogin
	repoName := g.repoName

	if ownerLogin == "" || repoName == "" {
		g.LatestStatus.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	opts := &github.ListOptions{PerPage: 1}
	statuses, _, err := conn.Client().Repositories.ListDeploymentStatuses(conn.Context(), ownerLogin, repoName, deploymentID, opts)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			g.LatestStatus.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		if strings.Contains(err.Error(), "403") {
			log.Debug().Msg("Deployment statuses are not accessible for this deployment")
			g.LatestStatus.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	if len(statuses) == 0 {
		g.LatestStatus.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	status := statuses[0]
	var creator *mqlGithubUser
	if status.Creator != nil {
		creatorRes, err := NewResource(g.MqlRuntime, "github.user", map[string]*llx.RawData{
			"id":    llx.IntDataDefault(status.Creator.ID, 0),
			"login": llx.StringDataPtr(status.Creator.Login),
		})
		if err != nil {
			return nil, err
		}
		creator = creatorRes.(*mqlGithubUser)
	}

	statusRes, err := CreateResource(g.MqlRuntime, "github.deploymentStatus", map[string]*llx.RawData{
		"id":             llx.IntDataDefault(status.ID, 0),
		"state":          llx.StringDataPtr(status.State),
		"description":    llx.StringDataPtr(status.Description),
		"environment":    llx.StringDataPtr(status.Environment),
		"creator":        creatorData(creator),
		"createdAt":      llx.TimeDataPtr(githubTimestamp(status.CreatedAt)),
		"updatedAt":      llx.TimeDataPtr(githubTimestamp(status.UpdatedAt)),
		"targetUrl":      llx.StringDataPtr(status.TargetURL),
		"logUrl":         llx.StringDataPtr(status.LogURL),
		"environmentUrl": llx.StringDataPtr(status.EnvironmentURL),
	})
	if err != nil {
		return nil, err
	}

	return statusRes.(*mqlGithubDeploymentStatus), nil
}
