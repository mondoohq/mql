// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/bitbucket/connection"
)

// mqlBitbucketRepositoryInternal caches the identifiers needed to resolve
// this repository's typed project() and workspace() references without
// re-parsing fullName or re-fetching the repository.
type mqlBitbucketRepositoryInternal struct {
	cacheWorkspaceSlug string
	cacheRepoSlug      string
	cacheProjectKey    string // empty when the repository has no project assigned
}

// newMqlBitbucketRepository maps a single API repository to its MQL resource.
func newMqlBitbucketRepository(runtime *plugin.Runtime, r *connection.Repository) (plugin.Resource, error) {
	var mainBranch string
	if r.MainBranch != nil {
		mainBranch = r.MainBranch.Name
	}

	res, err := CreateResource(runtime, "bitbucket.repository", map[string]*llx.RawData{
		"__id":        llx.StringData(r.FullName),
		"id":          llx.StringData(r.UUID),
		"slug":        llx.StringData(r.Slug),
		"fullName":    llx.StringData(r.FullName),
		"name":        llx.StringData(r.Name),
		"description": llx.StringData(r.Description),
		"isPrivate":   llx.BoolData(r.IsPrivate),
		"forkPolicy":  llx.StringData(r.ForkPolicy),
		"language":    llx.StringData(r.Language),
		"size":        llx.IntData(r.Size),
		"hasIssues":   llx.BoolData(r.HasIssues),
		"hasWiki":     llx.BoolData(r.HasWiki),
		"mainBranch":  llx.StringData(mainBranch),
		"createdOn":   llx.TimeDataPtr(r.CreatedOn),
		"updatedOn":   llx.TimeDataPtr(r.UpdatedOn),
	})
	if err != nil {
		return nil, err
	}

	mqlRepo := res.(*mqlBitbucketRepository)
	if r.Workspace != nil {
		mqlRepo.cacheWorkspaceSlug = r.Workspace.Slug
	}
	mqlRepo.cacheRepoSlug = r.Slug
	if r.Project != nil {
		mqlRepo.cacheProjectKey = r.Project.Key
	}
	return res, nil
}

// initBitbucketRepository resolves a repository by its full name
// (workspace/repo-slug) on demand, for typed references
// (branchRestriction.repository, deployKey.repository) and direct lookups
// such as bitbucket.repository(fullName: "acme-corp/api-service").
func initBitbucketRepository(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// fast path: the caller already provided a fully populated resource
	if len(args) > 2 {
		return args, nil, nil
	}

	fullNameArg, ok := args["fullName"]
	if !ok {
		return args, nil, nil
	}
	fullName, ok := fullNameArg.Value.(string)
	if !ok || fullName == "" {
		return nil, nil, fmt.Errorf("bitbucket.repository requires a valid fullName")
	}

	parts := strings.SplitN(fullName, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, nil, fmt.Errorf("bitbucket.repository fullName %q must be in the form workspace/repo-slug", fullName)
	}
	workspace, repoSlug := parts[0], parts[1]

	conn := runtime.Connection.(*connection.BitbucketConnection)
	r, err := conn.Client().GetRepository(context.Background(), workspace, repoSlug)
	if err != nil {
		return nil, nil, fmt.Errorf("bitbucket.repository with fullName %q not found: %w", fullName, err)
	}

	res, err := newMqlBitbucketRepository(runtime, r)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// project resolves the project this repository belongs to, or null when the
// repository has no project assigned.
func (r *mqlBitbucketRepository) project() (*mqlBitbucketProject, error) {
	if r.cacheProjectKey == "" {
		r.Project.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	res, err := NewResource(r.MqlRuntime, "bitbucket.project", map[string]*llx.RawData{
		"workspace": llx.StringData(r.cacheWorkspaceSlug),
		"key":       llx.StringData(r.cacheProjectKey),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlBitbucketProject), nil
}

// workspace resolves the workspace that owns this repository.
func (r *mqlBitbucketRepository) workspace() (*mqlBitbucketWorkspace, error) {
	res, err := NewResource(r.MqlRuntime, "bitbucket.workspace", map[string]*llx.RawData{
		"slug": llx.StringData(r.cacheWorkspaceSlug),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlBitbucketWorkspace), nil
}

// branchRestrictions lists every branch restriction rule configured on this
// repository.
func (r *mqlBitbucketRepository) branchRestrictions() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.BitbucketConnection)
	list, err := conn.Client().ListBranchRestrictions(context.Background(), r.cacheWorkspaceSlug, r.cacheRepoSlug)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(list))
	for i := range list {
		res, err := newMqlBitbucketBranchRestriction(r.MqlRuntime, r.FullName.Data, r.cacheWorkspaceSlug, &list[i])
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// deployKeys lists every deploy key registered on this repository.
func (r *mqlBitbucketRepository) deployKeys() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.BitbucketConnection)
	list, err := conn.Client().ListDeployKeys(context.Background(), r.cacheWorkspaceSlug, r.cacheRepoSlug)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(list))
	for i := range list {
		res, err := newMqlBitbucketDeployKey(r.MqlRuntime, r.FullName.Data, &list[i])
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// defaultReviewers lists the users required as reviewers on new pull
// requests for this repository.
func (r *mqlBitbucketRepository) defaultReviewers() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.BitbucketConnection)
	list, err := conn.Client().ListDefaultReviewers(context.Background(), r.cacheWorkspaceSlug, r.cacheRepoSlug)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(list))
	for _, u := range list {
		// Bitbucket does not attach a permission level to a default-reviewer
		// assignment, so it is left empty rather than guessed.
		res, err := newMqlBitbucketMember(r.MqlRuntime, u, "")
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}
