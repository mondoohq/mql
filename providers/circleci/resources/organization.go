// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/circleci/connection"
)

// newMqlCircleciOrganization maps a single API collaboration to its MQL
// organization resource.
func newMqlCircleciOrganization(runtime *plugin.Runtime, o connection.Collaboration) (plugin.Resource, error) {
	return CreateResource(runtime, "circleci.organization", map[string]*llx.RawData{
		"__id":    llx.StringData(o.ID),
		"id":      llx.StringData(o.ID),
		"name":    llx.StringData(o.Name),
		"vcsType": llx.StringData(o.VcsType),
	})
}

// initCircleciOrganization resolves an organization by its id on demand, for
// typed references (e.g. circleci.project.organization) that only carry the
// id. CircleCI API v2 has no get-organization-by-id endpoint, so the lookup
// walks the current token's visible organizations and matches by id.
func initCircleciOrganization(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// fast path: the caller already provided a fully populated resource
	if len(args) > 2 {
		return args, nil, nil
	}

	idArg, ok := args["id"]
	if !ok {
		return args, nil, nil
	}
	id, ok := idArg.Value.(string)
	if !ok || id == "" {
		return nil, nil, fmt.Errorf("circleci.organization requires a valid id")
	}

	conn := runtime.Connection.(*connection.CircleciConnection)
	orgs, err := conn.Client().GetCollaborations(context.Background())
	if err != nil {
		return nil, nil, err
	}
	for _, o := range orgs {
		if o.ID == id {
			res, err := newMqlCircleciOrganization(runtime, o)
			if err != nil {
				return nil, nil, err
			}
			return args, res, nil
		}
	}
	return nil, nil, fmt.Errorf("circleci.organization with id %q not found", id)
}

// projects lists every project owned by this organization. CircleCI API v2
// has no bulk list-projects endpoint, so projects are discovered by walking
// the organization's pipelines (the only org-scoped listing that carries a
// project_slug) and deduplicating by slug before fetching each project's
// full detail.
func (o *mqlCircleciOrganization) projects() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.CircleciConnection)
	client := conn.Client()

	orgSlug := connection.VcsSlugPrefix(o.VcsType.Data) + "/" + o.Name.Data

	seen := map[string]struct{}{}
	var slugs []string
	pageToken := ""
	for {
		resp, err := client.ListPipelines(context.Background(), orgSlug, pageToken)
		if err != nil {
			return nil, err
		}
		for _, p := range resp.Items {
			if p.ProjectSlug == "" {
				continue
			}
			if _, ok := seen[p.ProjectSlug]; ok {
				continue
			}
			seen[p.ProjectSlug] = struct{}{}
			slugs = append(slugs, p.ProjectSlug)
		}
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}

	all := make([]any, 0, len(slugs))
	for _, slug := range slugs {
		p, err := client.GetProject(context.Background(), slug)
		if err != nil {
			return nil, err
		}
		res, err := newMqlCircleciProject(o.MqlRuntime, p)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// contexts lists every context owned by this organization.
func (o *mqlCircleciOrganization) contexts() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.CircleciConnection)
	client := conn.Client()

	var all []any
	pageToken := ""
	for {
		resp, err := client.ListContexts(context.Background(), o.Id.Data, pageToken)
		if err != nil {
			return nil, err
		}
		for _, c := range resp.Items {
			res, err := newMqlCircleciContext(o.MqlRuntime, c, o.Id.Data)
			if err != nil {
				return nil, err
			}
			all = append(all, res)
		}
		if resp.NextPageToken == "" {
			break
		}
		pageToken = resp.NextPageToken
	}
	return all, nil
}
