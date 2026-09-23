// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

// pageSize is the per-request page size used for the SDK's manual pagination.
const pageSize = 500

// dictTime renders a time for inclusion in a dict field, using nil for the zero
// time so the value round-trips cleanly across the plugin boundary.
func dictTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.Format(time.RFC3339)
}

// newMqlMongodbatlasProject maps a project to its resource, shared by the
// projects list and the by-id init used by typed references.
func newMqlMongodbatlasProject(runtime *plugin.Runtime, p admin.Group) (*mqlMongodbatlasProject, error) {
	res, err := CreateResource(runtime, "mongodbatlas.project", map[string]*llx.RawData{
		"__id":                    llx.StringData("mongodbatlas.project/" + p.GetId()),
		"id":                      llx.StringData(p.GetId()),
		"name":                    llx.StringData(p.GetName()),
		"orgId":                   llx.StringData(p.GetOrgId()),
		"clusterCount":            llx.IntData(p.GetClusterCount()),
		"created":                 llx.TimeDataPtr(timePtr(p.GetCreated())),
		"regionUsageRestrictions": llx.StringData(p.GetRegionUsageRestrictions()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMongodbatlasProject), nil
}

// initMongodbatlasProject resolves a single project by id so typed references
// (such as an API key role assignment) can hydrate a full project from its id.
func initMongodbatlasProject(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok {
		return args, nil, nil
	}
	id, _ := idRaw.Value.(string)
	if id == "" {
		return nil, nil, fmt.Errorf("mongodbatlas.project requires a non-empty id")
	}
	p, _, err := atlasClient(runtime).ProjectsAPI.GetGroup(context.Background(), id).Execute()
	if err != nil {
		return nil, nil, err
	}
	res, err := newMqlMongodbatlasProject(runtime, *p)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (r *mqlMongodbatlas) projects() ([]any, error) {
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	for page := 1; ; page++ {
		resp, _, err := client.ProjectsAPI.ListGroups(ctx).ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			return nil, err
		}
		results := resp.GetResults()
		for i := range results {
			res, err := newMqlMongodbatlasProject(r.MqlRuntime, results[i])
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		if len(results) < pageSize {
			break
		}
	}
	return out, nil
}

// orgProjectsByID lists the organization's projects once and caches them by id
// on the root resource. Resolving a project reference through this map keeps a
// list of references to one API call, where hydrating each one by id would run
// the project init, and therefore a GetProject call, per reference.
func (r *mqlMongodbatlas) orgProjectsByID() (map[string]*mqlMongodbatlasProject, error) {
	r.projectsOnce.Do(func() {
		projects, err := r.projects()
		if err != nil {
			r.projectsErr = err
			return
		}
		m := make(map[string]*mqlMongodbatlasProject, len(projects))
		for _, p := range projects {
			proj, ok := p.(*mqlMongodbatlasProject)
			if !ok {
				continue
			}
			m[proj.Id.Data] = proj
		}
		r.projectsByID = m
	})
	return r.projectsByID, r.projectsErr
}

func (r *mqlMongodbatlas) orgUsers() ([]any, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	for page := 1; ; page++ {
		resp, _, err := client.MongoDBCloudUsersAPI.ListOrgUsers(ctx, oid).ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			return nil, err
		}
		results := resp.GetResults()
		for i := range results {
			res, err := newMqlMongodbatlasOrgUser(r.MqlRuntime, results[i])
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		if len(results) < pageSize {
			break
		}
	}
	return out, nil
}

type mqlMongodbatlasOrgUserInternal struct {
	cacheUserID       string
	cacheTeamIds      []string
	cacheProjectRoles []admin.GroupRoleAssignment
}

func newMqlMongodbatlasOrgUser(runtime *plugin.Runtime, u admin.OrgUserResponse) (*mqlMongodbatlasOrgUser, error) {
	roles := u.GetRoles()
	res, err := CreateResource(runtime, "mongodbatlas.orgUser", map[string]*llx.RawData{
		"__id":                llx.StringData("mongodbatlas.orgUser/" + u.GetId()),
		"id":                  llx.StringData(u.GetId()),
		"username":            llx.StringData(u.GetUsername()),
		"orgMembershipStatus": llx.StringData(u.GetOrgMembershipStatus()),
		"orgRoles":            llx.ArrayData(strSlice(roles.GetOrgRoles()), types.String),
		"lastAuth":            llx.TimeDataPtr(timePtr(u.GetLastAuth())),
		"createdAt":           llx.TimeDataPtr(timePtr(u.GetCreatedAt())),
		"invitationCreatedAt": llx.TimeDataPtr(timePtr(u.GetInvitationCreatedAt())),
		"invitationExpiresAt": llx.TimeDataPtr(timePtr(u.GetInvitationExpiresAt())),
		"inviterUsername":     llx.StringDataPtr(u.InviterUsername),
	})
	if err != nil {
		return nil, err
	}
	orgUser := res.(*mqlMongodbatlasOrgUser)
	orgUser.cacheUserID = u.GetId()
	orgUser.cacheTeamIds = u.GetTeamIds()
	orgUser.cacheProjectRoles = roles.GetGroupRoleAssignments()
	return orgUser, nil
}

type mqlMongodbatlasOrgUserProjectRoleInternal struct {
	cacheGroupID string
}

// projectRoles expands the member's project-level grants, one entry per project
// the member holds any role on. The assignments arrive with the org user
// listing, so this costs no additional API call.
func (r *mqlMongodbatlasOrgUser) projectRoles() ([]any, error) {
	out := []any{}
	for _, assignment := range r.cacheProjectRoles {
		groupID := assignment.GetGroupId()
		if groupID == "" {
			continue
		}
		res, err := CreateResource(r.MqlRuntime, "mongodbatlas.orgUser.projectRole", map[string]*llx.RawData{
			"__id":  llx.StringData("mongodbatlas.orgUser.projectRole/" + r.cacheUserID + "/" + groupID),
			"roles": llx.ArrayData(strSlice(assignment.GetGroupRoles()), types.String),
		})
		if err != nil {
			return nil, err
		}
		projectRole := res.(*mqlMongodbatlasOrgUserProjectRole)
		projectRole.cacheGroupID = groupID
		out = append(out, projectRole)
	}
	return out, nil
}

// resolveProject returns the project with the given id, preferring the
// organization's project listing so that a whole set of references costs one
// API call. Hydrating each reference by id instead would run the project init,
// and therefore a GetProject call, per reference. A project the organization
// listing does not cover, such as one reached through a credential scoped
// elsewhere, is fetched directly so it still resolves.
func resolveProject(runtime *plugin.Runtime, id string) (*mqlMongodbatlasProject, error) {
	root, err := rootMongodbatlas(runtime)
	if err != nil {
		return nil, err
	}
	projectsByID, err := root.orgProjectsByID()
	if err != nil {
		return nil, err
	}
	if p, ok := projectsByID[id]; ok {
		return p, nil
	}

	res, err := NewResource(runtime, "mongodbatlas.project", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	proj, ok := res.(*mqlMongodbatlasProject)
	if !ok || proj == nil {
		return nil, fmt.Errorf("mongodbatlas.project with id %q could not be resolved", id)
	}
	return proj, nil
}

// project resolves the project the roles are granted on.
func (r *mqlMongodbatlasOrgUserProjectRole) project() (*mqlMongodbatlasProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheGroupID)
}

// orgTeamsByID lists every team in the organization once and caches them by id
// on the root resource, so per-user team resolution is a map lookup rather than
// a GetTeamById call per membership.
func (r *mqlMongodbatlas) orgTeamsByID() (map[string]admin.TeamResponse, error) {
	r.teamsOnce.Do(func() {
		oid, err := orgID(r.MqlRuntime)
		if err != nil {
			r.teamsErr = err
			return
		}
		client := atlasClient(r.MqlRuntime)
		ctx := context.Background()

		m := map[string]admin.TeamResponse{}
		for page := 1; ; page++ {
			resp, httpResp, err := client.TeamsAPI.ListOrgTeams(ctx, oid).ItemsPerPage(pageSize).PageNum(page).Execute()
			if err != nil {
				// A project-scoped credential without org privilege cannot list
				// teams; record the denial rather than failing every user's
				// teams() through the cached error. Callers render null, since
				// no team could be resolved rather than none being held.
				if isAccessDenied(httpResp) {
					r.teamsByID = map[string]admin.TeamResponse{}
					r.teamsDenied = true
					return
				}
				r.teamsErr = err
				return
			}
			results := resp.GetResults()
			for i := range results {
				m[results[i].GetId()] = results[i]
			}
			if len(results) < pageSize {
				break
			}
		}
		r.teamsByID = m
	})
	return r.teamsByID, r.teamsErr
}

// teams resolves the member's team ids to the teams they belong to.
func (r *mqlMongodbatlasOrgUser) teams() ([]any, error) {
	root, err := rootMongodbatlas(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	teamsByID, err := root.orgTeamsByID()
	if err != nil {
		return nil, err
	}
	// The team listing was denied, so the member's memberships could not be
	// resolved. Reporting an empty list here would read as "belongs to no
	// team", which is a different and unverified claim.
	if root.teamsDenied {
		r.Teams.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	out := []any{}
	for _, teamID := range r.cacheTeamIds {
		t, ok := teamsByID[teamID]
		if !ok {
			continue
		}
		res, err := newMqlMongodbatlasTeam(r.MqlRuntime, t)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlMongodbatlas) teams() ([]any, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	for page := 1; ; page++ {
		resp, _, err := client.TeamsAPI.ListOrgTeams(ctx, oid).ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			return nil, err
		}
		results := resp.GetResults()
		for i := range results {
			res, err := newMqlMongodbatlasTeam(r.MqlRuntime, results[i])
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		if len(results) < pageSize {
			break
		}
	}
	return out, nil
}

func newMqlMongodbatlasTeam(runtime *plugin.Runtime, t admin.TeamResponse) (*mqlMongodbatlasTeam, error) {
	res, err := CreateResource(runtime, "mongodbatlas.team", map[string]*llx.RawData{
		"__id": llx.StringData("mongodbatlas.team/" + t.GetId()),
		"id":   llx.StringData(t.GetId()),
		"name": llx.StringData(t.GetName()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMongodbatlasTeam), nil
}

// users resolves the members of the team.
func (r *mqlMongodbatlasTeam) users() ([]any, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	for page := 1; ; page++ {
		resp, _, err := client.MongoDBCloudUsersAPI.ListTeamUsers(ctx, oid, r.Id.Data).ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			return nil, err
		}
		results := resp.GetResults()
		for i := range results {
			res, err := newMqlMongodbatlasOrgUser(r.MqlRuntime, results[i])
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		if len(results) < pageSize {
			break
		}
	}
	return out, nil
}

func (r *mqlMongodbatlas) apiKeys() ([]any, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	for page := 1; ; page++ {
		resp, _, err := client.ProgrammaticAPIKeysAPI.ListOrgApiKeys(ctx, oid).ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			return nil, err
		}
		results := resp.GetResults()
		for i := range results {
			k := results[i]
			res, err := CreateResource(r.MqlRuntime, "mongodbatlas.apiKey", map[string]*llx.RawData{
				"__id":        llx.StringData("mongodbatlas.apiKey/" + k.GetId()),
				"id":          llx.StringData(k.GetId()),
				"publicKey":   llx.StringData(k.GetPublicKey()),
				"description": llx.StringData(k.GetDesc()),
			})
			if err != nil {
				return nil, err
			}
			apiKey := res.(*mqlMongodbatlasApiKey)
			apiKey.cacheApiKeyID = k.GetId()
			apiKey.cacheRoles = k.GetRoles()
			out = append(out, apiKey)
		}
		if len(results) < pageSize {
			break
		}
	}
	return out, nil
}

type mqlMongodbatlasApiKeyInternal struct {
	cacheApiKeyID string
	cacheRoles    []admin.CloudAccessRoleAssignment
}

type mqlMongodbatlasApiKeyRoleAssignmentInternal struct {
	cacheGroupID string
}

// roleAssignments expands the key's granted roles into typed assignments, each
// carrying the role name and, for a project-scoped grant, the project.
func (r *mqlMongodbatlasApiKey) roleAssignments() ([]any, error) {
	out := []any{}
	for _, role := range r.cacheRoles {
		groupID := role.GetGroupId()
		orgLevel := groupID == ""
		scopeKey := groupID
		if orgLevel {
			scopeKey = "org/" + role.GetOrgId()
		}
		res, err := CreateResource(r.MqlRuntime, "mongodbatlas.apiKey.roleAssignment", map[string]*llx.RawData{
			"__id":     llx.StringData("mongodbatlas.apiKey.roleAssignment/" + r.cacheApiKeyID + "/" + role.GetRoleName() + "/" + scopeKey),
			"roleName": llx.StringData(role.GetRoleName()),
			"orgLevel": llx.BoolData(orgLevel),
		})
		if err != nil {
			return nil, err
		}
		ra := res.(*mqlMongodbatlasApiKeyRoleAssignment)
		ra.cacheGroupID = groupID
		out = append(out, ra)
	}
	return out, nil
}

// project resolves the project a project-scoped role applies to. Null for an
// organization-level role.
func (r *mqlMongodbatlasApiKeyRoleAssignment) project() (*mqlMongodbatlasProject, error) {
	if r.cacheGroupID == "" {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveProject(r.MqlRuntime, r.cacheGroupID)
}

func (r *mqlMongodbatlas) serviceAccounts() ([]any, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()

	out := []any{}
	for page := 1; ; page++ {
		resp, _, err := client.ServiceAccountsAPI.ListOrgServiceAccounts(ctx, oid).ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			return nil, err
		}
		results := resp.GetResults()
		for i := range results {
			sa := results[i]
			secrets := []any{}
			for _, s := range sa.GetSecrets() {
				secrets = append(secrets, map[string]any{
					"id":                s.GetId(),
					"createdAt":         dictTime(s.GetCreatedAt()),
					"expiresAt":         dictTime(s.GetExpiresAt()),
					"lastUsedAt":        dictTime(s.GetLastUsedAt()),
					"maskedSecretValue": s.GetMaskedSecretValue(),
				})
			}
			res, err := CreateResource(r.MqlRuntime, "mongodbatlas.serviceAccount", map[string]*llx.RawData{
				"__id":        llx.StringData("mongodbatlas.serviceAccount/" + sa.GetClientId()),
				"clientId":    llx.StringData(sa.GetClientId()),
				"name":        llx.StringData(sa.GetName()),
				"description": llx.StringData(sa.GetDescription()),
				"roles":       llx.ArrayData(strSlice(sa.GetRoles()), types.String),
				"createdAt":   llx.TimeDataPtr(timePtr(sa.GetCreatedAt())),
				"secrets":     llx.ArrayData(secrets, types.Dict),
			})
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		if len(results) < pageSize {
			break
		}
	}
	return out, nil
}
