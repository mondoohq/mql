// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// projectUsers lists the members holding a role on the project. The
// organization member listing carries the same grants, but only for a
// credential with organization privilege; this endpoint answers for a
// credential scoped to the project.
func (r *mqlMongodbatlas) projectUsers() ([]any, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	err = forEachPage(func(page int) (int, error) {
		resp, httpResp, err := client.MongoDBCloudUsersAPI.
			ListGroupUsers(ctx, pid).
			ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			if isAccessDenied(httpResp) {
				r.ProjectUsers.State = plugin.StateIsSet | plugin.StateIsNull
				out = nil
				return 0, nil
			}
			return 0, err
		}
		results := resp.GetResults()
		for i := range results {
			u := results[i]
			res, err := CreateResource(r.MqlRuntime, "mongodbatlas.projectUser", map[string]*llx.RawData{
				// A user id is global to Atlas, but the same user holds
				// different roles on each project they are a member of, so the
				// project belongs in the key.
				"__id":                llx.StringData("mongodbatlas.projectUser/" + pid + "/" + u.GetId()),
				"id":                  llx.StringData(u.GetId()),
				"username":            llx.StringData(u.GetUsername()),
				"roles":               llx.ArrayData(strSlice(u.GetRoles()), types.String),
				"orgMembershipStatus": llx.StringData(u.GetOrgMembershipStatus()),
				"lastAuth":            llx.TimeDataPtr(u.LastAuth),
				"createdAt":           llx.TimeDataPtr(u.CreatedAt),
				"invitationCreatedAt": llx.TimeDataPtr(u.InvitationCreatedAt),
				"invitationExpiresAt": llx.TimeDataPtr(u.InvitationExpiresAt),
				"inviterUsername":     llx.StringDataPtr(u.InviterUsername),
				"country":             llx.StringDataPtr(u.Country),
			})
			if err != nil {
				return 0, err
			}
			out = append(out, res)
		}
		return len(results), nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// mqlMongodbatlasProjectTeamInternal carries the team the grant applies to,
// which is resolved against the organization's team listing rather than fetched
// per grant.
type mqlMongodbatlasProjectTeamInternal struct {
	cacheTeamID string
}

// projectTeams lists the teams granted a role on the project. A team grant
// reaches every member of the team, so it carries further than the per-member
// assignments show.
func (r *mqlMongodbatlas) projectTeams() ([]any, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	err = forEachPage(func(page int) (int, error) {
		resp, httpResp, err := client.TeamsAPI.
			ListGroupTeams(ctx, pid).
			ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			if isAccessDenied(httpResp) {
				r.ProjectTeams.State = plugin.StateIsSet | plugin.StateIsNull
				out = nil
				return 0, nil
			}
			return 0, err
		}
		results := resp.GetResults()
		for i := range results {
			t := results[i]
			res, err := CreateResource(r.MqlRuntime, "mongodbatlas.projectTeam", map[string]*llx.RawData{
				"__id":  llx.StringData("mongodbatlas.projectTeam/" + pid + "/" + t.GetTeamId()),
				"roles": llx.ArrayData(strSlice(t.GetRoleNames()), types.String),
			})
			if err != nil {
				return 0, err
			}
			grant := res.(*mqlMongodbatlasProjectTeam)
			grant.cacheTeamID = t.GetTeamId()
			out = append(out, grant)
		}
		return len(results), nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// team resolves the team the roles are granted to, through the organization's
// team listing so a whole set of grants costs one call. Naming a team requires
// organization access, so a project-scoped credential leaves this null rather
// than reporting a team that was never read.
func (r *mqlMongodbatlasProjectTeam) team() (*mqlMongodbatlasTeam, error) {
	root, err := rootMongodbatlas(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	teamsByID, err := root.orgTeamsByID()
	if err != nil {
		return nil, err
	}
	t, ok := teamsByID[r.cacheTeamID]
	if !ok {
		r.Team.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlMongodbatlasTeam(r.MqlRuntime, t)
}

// projectInvitations lists the invitations to the project that have not been
// accepted. Each is a standing grant to whoever controls the invited address
// until it expires or is withdrawn.
func (r *mqlMongodbatlas) projectInvitations() ([]any, error) {
	pid, err := projectID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	// The invitation endpoint is not paginated: it answers with the complete
	// set of outstanding invitations for the project.
	invites, httpResp, err := client.ProjectsAPI.ListGroupInvites(ctx, pid).Execute()
	if err != nil {
		if isAccessDenied(httpResp) {
			r.ProjectInvitations.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	out := []any{}
	for i := range invites {
		inv := invites[i]
		res, err := CreateResource(r.MqlRuntime, "mongodbatlas.projectInvitation", map[string]*llx.RawData{
			"__id":            llx.StringData("mongodbatlas.projectInvitation/" + pid + "/" + inv.GetId()),
			"id":              llx.StringData(inv.GetId()),
			"username":        llx.StringDataPtr(inv.Username),
			"roles":           llx.ArrayData(strSlice(inv.GetRoles()), types.String),
			"inviterUsername": llx.StringDataPtr(inv.InviterUsername),
			"createdAt":       llx.TimeDataPtr(inv.CreatedAt),
			"expiresAt":       llx.TimeDataPtr(inv.ExpiresAt),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
