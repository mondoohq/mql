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

// mqlBitbucketGroupInternal caches the owning workspace slug so the
// workspace() and members() accessors can resolve without re-deriving it.
type mqlBitbucketGroupInternal struct {
	cacheWorkspaceSlug string
}

// newMqlBitbucketGroup maps a single API group (slug and name) to its MQL
// resource. Group slugs are unique within a workspace, not globally, so the
// cache key composes it with the workspace.
func newMqlBitbucketGroup(runtime *plugin.Runtime, workspaceSlug, slug, name string) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "bitbucket.group", map[string]*llx.RawData{
		"__id": llx.StringData(workspaceSlug + "/" + slug),
		"slug": llx.StringData(slug),
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}

	mqlGroup := res.(*mqlBitbucketGroup)
	mqlGroup.cacheWorkspaceSlug = workspaceSlug
	return res, nil
}

// initBitbucketGroup resolves a group by its slug within a workspace on
// demand, for typed references (branchRestriction.groups) and direct
// lookups such as bitbucket.group(slug: "administrators"). workspace
// defaults to the connection's selected workspace when omitted.
func initBitbucketGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// A caller that hands over a cache key is pointing at a group that was
	// already built through newMqlBitbucketGroup, which is the only place the
	// owning workspace gets attached; let the runtime serve it from the
	// cache. Everything else is a lookup by slug, whatever else rides along,
	// so the guard keys on that field rather than on an arg count.
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}

	slugArg, ok := args["slug"]
	if !ok {
		return nil, nil, fmt.Errorf("bitbucket.group requires a slug argument")
	}
	slug, ok := slugArg.Value.(string)
	if !ok || slug == "" {
		return nil, nil, fmt.Errorf("bitbucket.group requires a valid slug")
	}

	conn := runtime.Connection.(*connection.BitbucketConnection)
	workspace := conn.Workspace()
	if wsArg, ok := args["workspace"]; ok {
		if ws, ok := wsArg.Value.(string); ok && ws != "" {
			workspace = ws
		}
	}

	groups, err := conn.Client().ListGroupsLegacy(context.Background(), workspace)
	if err != nil {
		return nil, nil, fmt.Errorf("bitbucket.group: unable to list groups in workspace %q to resolve slug %q: %w", workspace, slug, err)
	}
	for _, g := range groups {
		if g.Slug != slug {
			continue
		}
		res, err := newMqlBitbucketGroup(runtime, workspace, g.Slug, g.Name)
		if err != nil {
			return nil, nil, err
		}
		return args, res, nil
	}

	return nil, nil, fmt.Errorf("bitbucket.group with workspace %q and slug %q: %w", workspace, slug, connection.ErrNotFound)
}

// workspace resolves the workspace this group belongs to.
func (g *mqlBitbucketGroup) workspace() (*mqlBitbucketWorkspace, error) {
	res, err := NewResource(g.MqlRuntime, "bitbucket.workspace", map[string]*llx.RawData{
		"slug": llx.StringData(g.cacheWorkspaceSlug),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlBitbucketWorkspace), nil
}

// members lists the members of this group, via Bitbucket's 1.0 API; see
// Client.ListGroupsLegacy for why. Bitbucket does not attach an individual
// permission level to group membership, so each member's permission is
// left empty.
func (g *mqlBitbucketGroup) members() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.BitbucketConnection)
	groups, err := conn.Client().ListGroupsLegacy(context.Background(), g.cacheWorkspaceSlug)
	if err != nil {
		return nil, err
	}

	for _, group := range groups {
		if group.Slug != g.Slug.Data {
			continue
		}
		all := make([]any, 0, len(group.Members))
		for _, u := range group.Members {
			res, err := newMqlBitbucketMember(g.MqlRuntime, u, "")
			if err != nil {
				return nil, err
			}
			all = append(all, res)
		}
		return all, nil
	}
	// The group was listed a moment ago and is gone now (renamed or deleted
	// in between). An empty list here would read as "no members" and let a
	// membership audit pass on data that was never read.
	return nil, fmt.Errorf("bitbucket.group with slug %q in workspace %q: %w", g.Slug.Data, g.cacheWorkspaceSlug, connection.ErrNotFound)
}
