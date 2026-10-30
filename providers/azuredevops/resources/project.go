// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azuredevops/connection"
)

// newProject builds the resource of a project that was listed.
func newProject(runtime *plugin.Runtime, p connection.Project) (*mqlAzuredevopsProject, error) {
	res, err := CreateResource(runtime, "azuredevops.project", map[string]*llx.RawData{
		"id":             llx.StringData(p.ID),
		"name":           llx.StringData(p.Name),
		"description":    llx.StringData(p.Description),
		"state":          llx.StringData(p.State),
		"visibility":     llx.StringData(p.Visibility),
		"url":            llx.StringData(p.URL),
		"lastUpdateTime": llx.TimeDataPtr(p.LastUpdateTime),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzuredevopsProject), nil
}

func (r *mqlAzuredevopsProject) id() (string, error) {
	return "azuredevops.project/" + r.Id.Data, nil
}

func (r *mqlAzuredevopsProject) repositories() ([]any, error) {
	listing, err := connectionOf(r.MqlRuntime).Listing(apiContext())
	if err != nil {
		return nil, err
	}

	for _, pl := range listing.Projects {
		if pl.Project.ID != r.Id.Data {
			continue
		}
		if pl.NoAccess != nil {
			return nil, fmt.Errorf("azure devops: the credential cannot list the repositories of project %q: %w", r.Name.Data, pl.NoAccess)
		}
		out := make([]any, 0, len(pl.Repos))
		for _, repo := range pl.Repos {
			res, err := newRepository(r.MqlRuntime, pl.Project.Name, repo)
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		return out, nil
	}
	return nil, fmt.Errorf("azure devops: project %q is not in the listing of the organization", r.Name.Data)
}
