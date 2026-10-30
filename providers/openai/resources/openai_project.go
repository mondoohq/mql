// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/openai/openai-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// mapProject builds the resource args for an openai.project. Both the
// collection path and the single-object init share it so the two paths cannot
// diverge.
func mapProject(p openai.Project) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":       llx.StringData(p.ID),
		"id":         llx.StringData(p.ID),
		"name":       llx.StringData(p.Name),
		"status":     llx.StringData(string(p.Status)),
		"createdAt":  llx.TimeDataPtr(unixToNullableTime(p.CreatedAt)),
		"archivedAt": llx.TimeDataPtr(unixToNullableTime(p.ArchivedAt)),
		"residency":  llx.StringDataPtr(emptyToNil(string(p.Residency))),
	}
}

func (r *mqlOpenai) projects() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.projects")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.Projects.ListAutoPaging(ctx, openai.AdminOrganizationProjectListParams{})
	var res []any
	for iter.Next() {
		p := iter.Current()
		mqlProject, err := CreateResource(r.MqlRuntime, "openai.project", mapProject(p))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlProject)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}
	return res, nil
}

func initOpenaiProject(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok || idRaw == nil || idRaw.Value == nil {
		return args, nil, nil
	}
	projectID, ok := idRaw.Value.(string)
	if !ok || projectID == "" {
		return args, nil, nil
	}

	conn := openaiConn(runtime)
	client, err := adminPlaneClient(conn, "openai.project")
	if err != nil {
		return nil, nil, err
	}
	if client == nil {
		return nil, nil, fmt.Errorf("cannot fetch project %s: no admin API key configured", projectID)
	}
	p, err := client.Admin.Organization.Projects.Get(context.Background(), projectID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get project %s: %w", projectID, err)
	}
	return mapProject(*p), nil, nil
}

func (r *mqlOpenaiProject) apiKeys() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.project.apiKeys")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.Projects.APIKeys.ListAutoPaging(ctx, r.Id.Data, openai.AdminOrganizationProjectAPIKeyListParams{})
	var res []any
	for iter.Next() {
		k := iter.Current()

		ownerType := k.Owner.Type
		var ownerName, ownerId string
		switch ownerType {
		case "user":
			ownerName = k.Owner.User.Email
			ownerId = k.Owner.User.ID
		case "service_account":
			ownerName = k.Owner.ServiceAccount.Name
			ownerId = k.Owner.ServiceAccount.ID
		}

		mqlKey, err := CreateResource(r.MqlRuntime, "openai.project.apiKey", map[string]*llx.RawData{
			"__id":          llx.StringData(k.ID),
			"id":            llx.StringData(k.ID),
			"name":          llx.StringData(k.Name),
			"redactedValue": llx.StringData(k.RedactedValue),
			"createdAt":     llx.TimeDataPtr(unixToNullableTime(k.CreatedAt)),
			"lastUsedAt":    llx.TimeDataPtr(unixToNullableTime(k.LastUsedAt)),
			"expiresAt":     llx.TimeDataPtr(unixToNullableTime(k.ExpiresAt)),
			"ownerType":     llx.StringData(ownerType),
			"ownerName":     llx.StringData(ownerName),
			"ownerId":       llx.StringData(ownerId),
		})
		if err != nil {
			return nil, err
		}
		key := mqlKey.(*mqlOpenaiProjectApiKey)
		key.cacheOwnerId = ownerId
		key.cacheProjectId = r.Id.Data
		res = append(res, mqlKey)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list project API keys: %w", err)
	}
	return res, nil
}

func (r *mqlOpenaiProject) serviceAccounts() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.project.serviceAccounts")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.Projects.ServiceAccounts.ListAutoPaging(ctx, r.Id.Data, openai.AdminOrganizationProjectServiceAccountListParams{})
	var res []any
	for iter.Next() {
		sa := iter.Current()

		mqlSA, err := CreateResource(r.MqlRuntime, "openai.project.serviceAccount", map[string]*llx.RawData{
			"__id":      llx.StringData(sa.ID),
			"id":        llx.StringData(sa.ID),
			"name":      llx.StringData(sa.Name),
			"role":      llx.StringData(string(sa.Role)),
			"createdAt": llx.TimeDataPtr(unixToNullableTime(sa.CreatedAt)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSA)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list project service accounts: %w", err)
	}
	return res, nil
}

func (r *mqlOpenaiProject) users() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.project.users")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.Projects.Users.ListAutoPaging(ctx, r.Id.Data, openai.AdminOrganizationProjectUserListParams{})
	var res []any
	for iter.Next() {
		u := iter.Current()

		// the same user belongs to several projects, so the membership is keyed
		// by project as well as by user
		mqlUser, err := CreateResource(r.MqlRuntime, "openai.project.user", map[string]*llx.RawData{
			"__id":    llx.StringData(r.Id.Data + "/" + u.ID),
			"id":      llx.StringData(u.ID),
			"email":   llx.StringData(u.Email),
			"name":    llx.StringData(u.Name),
			"role":    llx.StringData(u.Role),
			"addedAt": llx.TimeDataPtr(unixToNullableTime(u.AddedAt)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlUser)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list project members: %w", err)
	}
	return res, nil
}

func (r *mqlOpenaiProjectUser) user() (*mqlOpenaiOrganizationUser, error) {
	return resolveOrganizationUser(r.MqlRuntime, r.Id.Data)
}

func (r *mqlOpenaiProject) groups() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.project.groups")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.Projects.Groups.ListAutoPaging(ctx, r.Id.Data, openai.AdminOrganizationProjectGroupListParams{})
	var res []any
	for iter.Next() {
		pg := iter.Current()
		mqlGroup, err := NewResource(r.MqlRuntime, "openai.group", map[string]*llx.RawData{
			"id": llx.StringData(pg.GroupID),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGroup)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list project groups: %w", err)
	}
	return res, nil
}

func (r *mqlOpenaiProject) roles() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.project.roles")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.Projects.Roles.ListAutoPaging(ctx, r.Id.Data, openai.AdminOrganizationProjectRoleListParams{})
	var res []any
	for iter.Next() {
		role := iter.Current()
		mqlRole, err := CreateResource(r.MqlRuntime, "openai.role",
			roleArgs(role.ID, role.Name, role.Description, role.ResourceType, role.Permissions, role.PredefinedRole))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRole)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list project roles: %w", err)
	}
	return res, nil
}

// openaiProjectList returns the organization project collection through the
// openai resource so the underlying list call is made once per scan.
func openaiProjectList(runtime *plugin.Runtime) ([]any, error) {
	obj, err := CreateResource(runtime, "openai", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	projects := obj.(*mqlOpenai).GetProjects()
	if projects.Error != nil {
		return nil, projects.Error
	}
	return projects.Data, nil
}

// resolveProject finds the project with the given id in the organization
// project list. Resolving through the cached list keeps a reference from
// costing a get per referring object. An audit log entry or a checkpoint grant
// can name a project that has since been deleted, so a miss is reported as
// (nil, nil) for the caller to null rather than as an error.
func resolveProject(runtime *plugin.Runtime, projectID string) (*mqlOpenaiProject, error) {
	projects, err := openaiProjectList(runtime)
	if err != nil {
		return nil, err
	}
	for i := range projects {
		p, ok := projects[i].(*mqlOpenaiProject)
		if !ok {
			continue
		}
		if p.Id.Data == projectID {
			return p, nil
		}
	}
	return nil, nil
}

type mqlOpenaiProjectApiKeyInternal struct {
	cacheOwnerId   string
	cacheProjectId string
}

func (r *mqlOpenaiProjectApiKey) owner() (*mqlOpenaiOrganizationUser, error) {
	if r.OwnerType.Data != "user" || r.cacheOwnerId == "" {
		r.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// a key outlives the member it was issued to, so an owner who has left the
	// organization nulls the field rather than failing the key list
	user, err := findOrganizationUser(r.MqlRuntime, r.cacheOwnerId)
	if err != nil {
		return nil, err
	}
	if user == nil {
		r.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return user, nil
}

func (r *mqlOpenaiProjectApiKey) serviceAccount() (*mqlOpenaiProjectServiceAccount, error) {
	if r.OwnerType.Data != "service_account" || r.cacheOwnerId == "" || r.cacheProjectId == "" {
		r.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	project, err := resolveProject(r.MqlRuntime, r.cacheProjectId)
	if err != nil {
		return nil, err
	}
	if project == nil {
		r.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	accounts := project.GetServiceAccounts()
	if accounts.Error != nil {
		return nil, accounts.Error
	}
	for i := range accounts.Data {
		sa, ok := accounts.Data[i].(*mqlOpenaiProjectServiceAccount)
		if !ok {
			continue
		}
		if sa.Id.Data == r.cacheOwnerId {
			return sa, nil
		}
	}
	r.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
