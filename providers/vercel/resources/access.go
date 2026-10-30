// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vercel/connection"
)

// mqlVercelAccessGroupInternal caches the team an access group belongs to so its
// members and project grants can be listed with the correct scope.
type mqlVercelAccessGroupInternal struct {
	teamID string
}

// mqlVercelAccessGroupProjectInternal caches the scope needed to resolve the
// typed project reference on a grant, plus the project object the grants
// endpoint embeds, so project() can avoid a per-grant project-by-id fetch.
type mqlVercelAccessGroupProjectInternal struct {
	teamID       string
	projectID    string
	cacheProject *projectRecord
}

// --- project members ------------------------------------------------------

type projectMemberRecord struct {
	UID       string   `json:"uid"`
	Email     string   `json:"email"`
	Username  string   `json:"username"`
	Name      string   `json:"name"`
	Role      string   `json:"role"`
	CreatedAt flexTime `json:"createdAt"`
}

func (p *mqlVercelProject) members() ([]any, error) {
	conn := p.MqlRuntime.Connection.(*connection.VercelConnection)
	records, err := connection.GetPaged[projectMemberRecord](context.Background(), conn, "/v1/projects/"+p.Id.Data+"/members", connection.TeamQuery(p.teamID), "members")
	if err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			p.Members.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		member, err := CreateResource(p.MqlRuntime, "vercel.project.member", map[string]*llx.RawData{
			"__id":      llx.StringData(p.Id.Data + "/" + rec.UID),
			"uid":       llx.StringData(rec.UID),
			"email":     llx.StringData(rec.Email),
			"username":  llx.StringData(rec.Username),
			"name":      llx.StringData(rec.Name),
			"role":      llx.StringData(rec.Role),
			"createdAt": llx.TimeDataPtr(rec.CreatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, member)
	}
	return res, nil
}

// --- access group members -------------------------------------------------

type accessGroupMemberRecord struct {
	UID       string   `json:"uid"`
	Email     string   `json:"email"`
	Username  string   `json:"username"`
	Name      string   `json:"name"`
	TeamRole  string   `json:"teamRole"`
	CreatedAt flexTime `json:"createdAt"`
}

func (g *mqlVercelAccessGroup) members() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.VercelConnection)
	query := connection.TeamQuery(g.teamID)
	query.Set("limit", "100")
	records, err := connection.GetPagedCursor[accessGroupMemberRecord](context.Background(), conn, "/v1/access-groups/"+g.Id.Data+"/members", query, "members")
	if err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			g.Members.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		// A 404 means the collection is not provisioned for this scope,
		// which genuinely is none.
		if connection.IsNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		member, err := CreateResource(g.MqlRuntime, "vercel.accessGroup.member", map[string]*llx.RawData{
			"__id":      llx.StringData(g.Id.Data + "/" + rec.UID),
			"uid":       llx.StringData(rec.UID),
			"email":     llx.StringData(rec.Email),
			"username":  llx.StringData(rec.Username),
			"name":      llx.StringData(rec.Name),
			"teamRole":  llx.StringData(rec.TeamRole),
			"createdAt": llx.TimeDataPtr(rec.CreatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, member)
	}
	return res, nil
}

// --- access group project grants ------------------------------------------

type accessGroupProjectRecord struct {
	ProjectID string         `json:"projectId"`
	Role      string         `json:"role"`
	CreatedAt flexTime       `json:"createdAt"`
	UpdatedAt flexTime       `json:"updatedAt"`
	Project   *projectRecord `json:"project"`
}

func (g *mqlVercelAccessGroup) projects() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.VercelConnection)
	query := connection.TeamQuery(g.teamID)
	query.Set("limit", "100")
	records, err := connection.GetPagedCursor[accessGroupProjectRecord](context.Background(), conn, "/v1/access-groups/"+g.Id.Data+"/projects", query, "projects")
	if err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			g.Projects.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		// A 404 means the collection is not provisioned for this scope,
		// which genuinely is none.
		if connection.IsNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}

	var res []any
	for i := range records {
		rec := records[i]
		resource, err := CreateResource(g.MqlRuntime, "vercel.accessGroup.project", map[string]*llx.RawData{
			"__id":      llx.StringData(g.Id.Data + "/" + rec.ProjectID),
			"role":      llx.StringData(rec.Role),
			"createdAt": llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt": llx.TimeDataPtr(rec.UpdatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		grant := resource.(*mqlVercelAccessGroupProject)
		grant.teamID = g.teamID
		grant.projectID = rec.ProjectID
		grant.cacheProject = rec.Project
		res = append(res, grant)
	}
	return res, nil
}

func (p *mqlVercelAccessGroupProject) project() (*mqlVercelProject, error) {
	if p.projectID == "" {
		p.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// The access-group projects endpoint embeds the full project object in each
	// grant; build the typed reference from it and skip the per-grant fetch.
	if p.cacheProject != nil && (p.cacheProject.ID != "" || p.cacheProject.Name != "") {
		rec := *p.cacheProject
		if rec.ID == "" {
			rec.ID = p.projectID
		}
		return newVercelProject(p.MqlRuntime, p.teamID, &rec)
	}

	conn := p.MqlRuntime.Connection.(*connection.VercelConnection)
	var rec projectRecord
	if err := conn.Get(context.Background(), "/v9/projects/"+p.projectID, connection.TeamQuery(p.teamID), &rec); err != nil {
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			p.Project.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	if rec.ID == "" {
		rec.ID = p.projectID
	}
	return newVercelProject(p.MqlRuntime, p.teamID, &rec)
}
