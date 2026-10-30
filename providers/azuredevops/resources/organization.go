// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func initAzuredevopsOrganization(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := connectionOf(runtime)
	data, err := conn.ConnectionData(apiContext())
	if err != nil {
		return nil, nil, err
	}

	args["name"] = llx.StringData(conn.Organization())
	args["id"] = llx.StringData(data.InstanceID)
	args["deploymentType"] = llx.StringData(data.DeploymentType)
	return args, nil, nil
}

func (r *mqlAzuredevopsOrganization) id() (string, error) {
	return "azuredevops.organization/" + r.Name.Data, nil
}

func (r *mqlAzuredevopsOrganization) projects() ([]any, error) {
	listing, err := connectionOf(r.MqlRuntime).Listing(apiContext())
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(listing.Projects))
	for _, p := range listing.Projects {
		res, err := newProject(r.MqlRuntime, p.Project)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlAzuredevopsOrganization) repositories() ([]any, error) {
	listing, err := connectionOf(r.MqlRuntime).Listing(apiContext())
	if err != nil {
		return nil, err
	}

	repos := listing.Repos()
	out := make([]any, 0, len(repos))
	for _, l := range repos {
		res, err := newRepository(r.MqlRuntime, l.Project.Name, l.Repo)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlAzuredevopsOrganization) unreadableProjects() ([]any, error) {
	listing, err := connectionOf(r.MqlRuntime).Listing(apiContext())
	if err != nil {
		return nil, err
	}

	names := listing.Unreadable()
	out := make([]any, 0, len(names))
	for _, n := range names {
		out = append(out, n)
	}
	return out, nil
}
