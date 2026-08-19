// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/bitbucket/connection"
)

// mqlBitbucketProjectInternal caches the owning workspace slug so the
// workspace accessor can resolve a typed bitbucket.workspace reference
// without re-deriving it from the project's embedded workspace payload.
type mqlBitbucketProjectInternal struct {
	cacheWorkspaceSlug string
}

// newMqlBitbucketProject maps a single API project to its MQL resource.
// workspaceSlug is the workspace the project was listed/read from; it is
// preferred over p.Workspace (which may be nil on some responses) for
// building the project's cache key and its typed workspace() reference.
func newMqlBitbucketProject(runtime *plugin.Runtime, workspaceSlug string, p *connection.Project) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "bitbucket.project", map[string]*llx.RawData{
		"__id":        llx.StringData(workspaceSlug + "/" + p.Key),
		"id":          llx.StringData(p.UUID),
		"key":         llx.StringData(p.Key),
		"name":        llx.StringData(p.Name),
		"isPrivate":   llx.BoolData(p.IsPrivate),
		"description": llx.StringData(p.Description),
		"createdOn":   llx.TimeDataPtr(p.CreatedOn),
		"updatedOn":   llx.TimeDataPtr(p.UpdatedOn),
	})
	if err != nil {
		return nil, err
	}

	mqlProject := res.(*mqlBitbucketProject)
	mqlProject.cacheWorkspaceSlug = workspaceSlug
	return res, nil
}

// initBitbucketProject resolves a project by its key within a workspace on
// demand, for typed references (repository.project) and direct lookups such
// as bitbucket.project(key: "ENG"). workspace defaults to the connection's
// selected workspace when omitted.
func initBitbucketProject(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// fast path: the caller already provided a fully populated resource
	if len(args) > 2 {
		return args, nil, nil
	}

	keyArg, ok := args["key"]
	if !ok {
		return nil, nil, fmt.Errorf("bitbucket.project requires a key argument")
	}
	key, ok := keyArg.Value.(string)
	if !ok || key == "" {
		return nil, nil, fmt.Errorf("bitbucket.project requires a valid key")
	}

	conn := runtime.Connection.(*connection.BitbucketConnection)
	workspace := conn.Workspace()
	if wsArg, ok := args["workspace"]; ok {
		if ws, ok := wsArg.Value.(string); ok && ws != "" {
			workspace = ws
		}
	}

	p, err := conn.Client().GetProject(context.Background(), workspace, key)
	if err != nil {
		return nil, nil, fmt.Errorf("bitbucket.project with workspace %q and key %q not found: %w", workspace, key, err)
	}

	res, err := newMqlBitbucketProject(runtime, workspace, p)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// workspace resolves the workspace that owns this project.
func (p *mqlBitbucketProject) workspace() (*mqlBitbucketWorkspace, error) {
	res, err := NewResource(p.MqlRuntime, "bitbucket.workspace", map[string]*llx.RawData{
		"slug": llx.StringData(p.cacheWorkspaceSlug),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlBitbucketWorkspace), nil
}

// repositories lists every repository in this project.
func (p *mqlBitbucketProject) repositories() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.BitbucketConnection)
	list, err := conn.Client().ListRepositoriesByProject(context.Background(), p.cacheWorkspaceSlug, p.Key.Data)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(list))
	for i := range list {
		res, err := newMqlBitbucketRepository(p.MqlRuntime, &list[i])
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// userPermissions lists the users granted an explicit permission on this
// project together with the permission level.
func (p *mqlBitbucketProject) userPermissions() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.BitbucketConnection)
	list, err := conn.Client().ListProjectUserPermissions(context.Background(), p.cacheWorkspaceSlug, p.Key.Data)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(list))
	for _, gp := range list {
		res, err := newMqlBitbucketMember(p.MqlRuntime, gp.User, gp.Permission)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// groupPermissions lists the groups granted an explicit permission on this
// project.
func (p *mqlBitbucketProject) groupPermissions() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.BitbucketConnection)
	list, err := conn.Client().ListProjectGroupPermissions(context.Background(), p.cacheWorkspaceSlug, p.Key.Data)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(list))
	for _, gp := range list {
		res, err := newMqlBitbucketGroup(p.MqlRuntime, p.cacheWorkspaceSlug, gp.Group.Slug, gp.Group.Name)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}
