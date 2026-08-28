// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/bitbucket/connection"
)

// mqlBitbucketRepositoryDeploymentInternal caches the identifiers needed to
// resolve this environment's typed repository() reference and to list its
// scoped Pipelines variables.
type mqlBitbucketRepositoryDeploymentInternal struct {
	cacheRepoFullName  string
	cacheWorkspaceSlug string
	cacheRepoSlug      string
	cacheEnvUUID       string
}

// newMqlBitbucketDeployment maps a single API deployment environment to its
// MQL resource. Environment UUIDs are unique within a repository, so the cache
// key composes the UUID with the owning repository's full name.
func newMqlBitbucketDeployment(runtime *plugin.Runtime, repoFullName, workspaceSlug, repoSlug string, e *connection.Environment) (plugin.Resource, error) {
	// An environment whose tier the API does not report stays null rather
	// than claiming a tier outside the documented set.
	var envType *string
	if e.EnvironmentType != nil {
		envType = &e.EnvironmentType.Name
	}

	res, err := CreateResource(runtime, "bitbucket.repository.deployment", map[string]*llx.RawData{
		"__id":            llx.StringData(repoFullName + "/environments/" + e.UUID),
		"id":              llx.StringData(e.UUID),
		"name":            llx.StringData(e.Name),
		"environmentType": llx.StringDataPtr(envType),
	})
	if err != nil {
		return nil, err
	}

	mqlEnv := res.(*mqlBitbucketRepositoryDeployment)
	mqlEnv.cacheRepoFullName = repoFullName
	mqlEnv.cacheWorkspaceSlug = workspaceSlug
	mqlEnv.cacheRepoSlug = repoSlug
	mqlEnv.cacheEnvUUID = e.UUID
	return res, nil
}

// repository resolves the repository this deployment environment belongs to.
func (d *mqlBitbucketRepositoryDeployment) repository() (*mqlBitbucketRepository, error) {
	res, err := NewResource(d.MqlRuntime, "bitbucket.repository", map[string]*llx.RawData{
		"fullName": llx.StringData(d.cacheRepoFullName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlBitbucketRepository), nil
}

// pipelineVariables lists the Pipelines variables scoped to this deployment
// environment.
func (d *mqlBitbucketRepositoryDeployment) pipelineVariables() ([]any, error) {
	conn := d.MqlRuntime.Connection.(*connection.BitbucketConnection)
	list, err := conn.Client().ListDeploymentVariables(context.Background(), d.cacheWorkspaceSlug, d.cacheRepoSlug, d.cacheEnvUUID)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(list))
	for i := range list {
		res, err := newMqlBitbucketPipelineVariable(d.MqlRuntime, d.cacheRepoFullName+"/environments/"+d.cacheEnvUUID, &list[i])
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}
