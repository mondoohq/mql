// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	together "github.com/togethercomputer/together-go"
	"go.mondoo.com/mql/llx"
)

func (r *mqlTogether) projects() ([]any, error) {
	client := togetherConn(r.MqlRuntime).Client()

	projects, err := collectPages(client.Projects.List(context.Background(), together.ProjectListParams{}))
	if err != nil {
		return nil, classifyRefusal(err)
	}

	res := make([]any, 0, len(projects))
	for _, p := range projects {
		mqlProject, err := CreateResource(r.MqlRuntime, "together.project", map[string]*llx.RawData{
			"__id":             llx.StringData(p.ID),
			"id":               llx.StringData(p.ID),
			"name":             llx.StringData(p.Name),
			"slug":             llx.StringData(p.Slug),
			"organizationId":   llx.StringData(p.OrganizationID),
			"organizationName": llx.StringData(p.OrganizationName),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlProject)
	}
	return res, nil
}

func (r *mqlTogetherProject) id() (string, error) {
	return r.Id.Data, nil
}
