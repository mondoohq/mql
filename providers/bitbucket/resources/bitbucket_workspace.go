// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/bitbucket/connection"
)

// newMqlBitbucketWorkspace maps a single API workspace to its MQL resource.
func newMqlBitbucketWorkspace(runtime *plugin.Runtime, w *connection.Workspace) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "bitbucket.workspace", map[string]*llx.RawData{
		"__id":              llx.StringData(w.Slug),
		"id":                llx.StringData(w.UUID),
		"slug":              llx.StringData(w.Slug),
		"name":              llx.StringData(w.Name),
		"isPrivate":         llx.BoolDataPtr(w.IsPrivate),
		"isPrivacyEnforced": llx.BoolDataPtr(w.IsPrivacyEnforced),
		"createdOn":         llx.TimeDataPtr(w.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// initBitbucketWorkspace resolves a workspace by its slug on demand, for
// typed references (project.workspace, repository.workspace, group.workspace)
// and direct lookups such as bitbucket.workspace(slug: "acme-corp"). When no
// slug is given (a bare bitbucket.workspace query), it defaults to the
// workspace selected by the connection (BITBUCKET_WORKSPACE or --workspace).
func initBitbucketWorkspace(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// fast path: the caller already provided a fully populated resource
	if len(args) > 1 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.BitbucketConnection)

	// Resolve the slug: prefer an explicit slug argument, otherwise default to
	// the workspace selected by the connection (BITBUCKET_WORKSPACE or
	// --workspace) so `bitbucket.workspace` can be queried directly.
	var slug string
	if slugArg, ok := args["slug"]; ok {
		s, ok := slugArg.Value.(string)
		if !ok || s == "" {
			return nil, nil, fmt.Errorf("bitbucket.workspace requires a valid slug")
		}
		slug = s
	} else {
		slug = conn.Workspace()
		if slug == "" {
			return nil, nil, fmt.Errorf("bitbucket.workspace requires a slug or a connection-selected workspace")
		}
	}

	// Reuse the workspace record Verify() already fetched during Connect,
	// when it's the same workspace, to avoid a redundant round trip.
	w := conn.VerifiedWorkspace()
	if w == nil || w.Slug != slug {
		fetched, err := conn.Client().GetWorkspace(context.Background(), slug)
		if err != nil {
			return nil, nil, fmt.Errorf("bitbucket.workspace with slug %q not found: %w", slug, err)
		}
		w = fetched
	}

	res, err := newMqlBitbucketWorkspace(runtime, w)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// projects lists every project in the workspace.
func (w *mqlBitbucketWorkspace) projects() ([]any, error) {
	conn := w.MqlRuntime.Connection.(*connection.BitbucketConnection)
	list, err := conn.Client().ListProjects(context.Background(), w.Slug.Data)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(list))
	for i := range list {
		res, err := newMqlBitbucketProject(w.MqlRuntime, w.Slug.Data, &list[i])
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// repositories lists every repository in the workspace.
func (w *mqlBitbucketWorkspace) repositories() ([]any, error) {
	conn := w.MqlRuntime.Connection.(*connection.BitbucketConnection)
	list, err := conn.Client().ListRepositories(context.Background(), w.Slug.Data)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(list))
	for i := range list {
		res, err := newMqlBitbucketRepository(w.MqlRuntime, &list[i])
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// members lists every member of the workspace together with their
// permission level.
func (w *mqlBitbucketWorkspace) members() ([]any, error) {
	conn := w.MqlRuntime.Connection.(*connection.BitbucketConnection)
	list, err := conn.Client().ListWorkspaceMembers(context.Background(), w.Slug.Data)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(list))
	for _, p := range list {
		res, err := newMqlBitbucketMember(w.MqlRuntime, p.User, p.Permission)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// groups lists every group defined in the workspace, via Bitbucket's 1.0 API
// (see Client.ListGroupsLegacy); the 2.0 API exposes no workspace-level group
// listing.
func (w *mqlBitbucketWorkspace) groups() ([]any, error) {
	conn := w.MqlRuntime.Connection.(*connection.BitbucketConnection)
	list, err := conn.Client().ListGroupsLegacy(context.Background(), w.Slug.Data)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(list))
	for _, g := range list {
		res, err := newMqlBitbucketGroup(w.MqlRuntime, w.Slug.Data, g.Slug, g.Name)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// webhooks lists every webhook configured at the workspace level.
func (w *mqlBitbucketWorkspace) webhooks() ([]any, error) {
	conn := w.MqlRuntime.Connection.(*connection.BitbucketConnection)
	list, err := conn.Client().ListWorkspaceWebhooks(context.Background(), w.Slug.Data)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(list))
	for i := range list {
		res, err := newMqlBitbucketWorkspaceWebhook(w.MqlRuntime, w.Slug.Data, &list[i])
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// pipelineVariables lists the Pipelines variables defined for the workspace.
func (w *mqlBitbucketWorkspace) pipelineVariables() ([]any, error) {
	conn := w.MqlRuntime.Connection.(*connection.BitbucketConnection)
	list, err := conn.Client().ListWorkspacePipelineVariables(context.Background(), w.Slug.Data)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(list))
	for i := range list {
		res, err := newMqlBitbucketPipelineVariable(w.MqlRuntime, w.Slug.Data, &list[i])
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// strList converts a []string (as returned by the SDK) into an MQL string
// array value, treating a nil slice as an empty list.
func strList(s []string) []any {
	res := make([]any, 0, len(s))
	for _, v := range s {
		res = append(res, v)
	}
	return res
}
