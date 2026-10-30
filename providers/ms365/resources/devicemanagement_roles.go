// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	betadm "github.com/microsoftgraph/msgraph-beta-sdk-go/devicemanagement"
	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

func (m *mqlMicrosoftDevicemanagementRoleDefinition) id() (string, error) {
	return m.Id.Data, nil
}

func (m *mqlMicrosoftDevicemanagementRoleAssignment) id() (string, error) {
	return m.Id.Data, nil
}

func (m *mqlMicrosoftDevicemanagementRoleScopeTag) id() (string, error) {
	return m.Id.Data, nil
}

func (a *mqlMicrosoftDevicemanagement) roleDefinitions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().RoleDefinitions().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	definitions, err := iterate[betamodels.RoleDefinitionable](ctx, resp, graphClient.GetAdapter(), betamodels.CreateRoleDefinitionCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, def := range definitions {
		permissions := rolePermissionsToDicts(def.GetRolePermissions())
		scopeTagIds := def.GetRoleScopeTagIds()
		if scopeTagIds == nil {
			scopeTagIds = []string{}
		}
		r, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement.roleDefinition",
			map[string]*llx.RawData{
				"__id":            llx.StringDataPtr(def.GetId()),
				"id":              llx.StringDataPtr(def.GetId()),
				"displayName":     llx.StringDataPtr(def.GetDisplayName()),
				"description":     llx.StringDataPtr(def.GetDescription()),
				"isBuiltIn":       llx.BoolDataPtr(def.GetIsBuiltIn()),
				"rolePermissions": llx.ArrayData(permissions, types.Any),
				"roleScopeTagIds": llx.ArrayData(stringsToAny(scopeTagIds), types.String),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func rolePermissionsToDicts(perms []betamodels.RolePermissionable) []any {
	res := []any{}
	for _, p := range perms {
		entry := map[string]any{}
		actions := []any{}
		for _, ra := range p.GetResourceActions() {
			actionMap := map[string]any{}
			actionMap["allowedResourceActions"] = stringsToAny(ra.GetAllowedResourceActions())
			actionMap["notAllowedResourceActions"] = stringsToAny(ra.GetNotAllowedResourceActions())
			actions = append(actions, actionMap)
		}
		entry["resourceActions"] = actions
		res = append(res, entry)
	}
	return res
}

func stringsToAny(s []string) []any {
	res := make([]any, len(s))
	for i, v := range s {
		res[i] = v
	}
	return res
}

func (a *mqlMicrosoftDevicemanagement) roleAssignments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	// $expand=roleDefinition so roleDefinitionId is populated from the nav property.
	reqConfig := &betadm.RoleAssignmentsRequestBuilderGetRequestConfiguration{
		QueryParameters: &betadm.RoleAssignmentsRequestBuilderGetQueryParameters{
			Expand: []string{"roleDefinition"},
		},
	}
	resp, err := graphClient.DeviceManagement().RoleAssignments().Get(ctx, reqConfig)
	if err != nil {
		return nil, transformError(err)
	}
	assignments, err := iterate[betamodels.DeviceAndAppManagementRoleAssignmentable](ctx, resp, graphClient.GetAdapter(), betamodels.CreateDeviceAndAppManagementRoleAssignmentCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, ra := range assignments {
		members := ra.GetMembers()
		if members == nil {
			members = []string{}
		}
		scopeMembers := ra.GetScopeMembers()
		if scopeMembers == nil {
			scopeMembers = []string{}
		}
		resourceScopes := ra.GetResourceScopes()
		if resourceScopes == nil {
			resourceScopes = []string{}
		}
		roleDefinitionId := ""
		if rd := ra.GetRoleDefinition(); rd != nil {
			if v := rd.GetId(); v != nil {
				roleDefinitionId = *v
			}
		}
		r, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement.roleAssignment",
			map[string]*llx.RawData{
				"__id":             llx.StringDataPtr(ra.GetId()),
				"id":               llx.StringDataPtr(ra.GetId()),
				"displayName":      llx.StringDataPtr(ra.GetDisplayName()),
				"description":      llx.StringDataPtr(ra.GetDescription()),
				"roleDefinitionId": llx.StringData(roleDefinitionId),
				"members":          llx.ArrayData(stringsToAny(members), types.String),
				"scopeMembers":     llx.ArrayData(stringsToAny(scopeMembers), types.String),
				"resourceScopes":   llx.ArrayData(stringsToAny(resourceScopes), types.String),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (a *mqlMicrosoftDevicemanagement) roleScopeTags() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.BetaGraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().RoleScopeTags().Get(ctx, nil)
	if err != nil {
		return nil, transformError(err)
	}
	tags, err := iterate[betamodels.RoleScopeTagable](ctx, resp, graphClient.GetAdapter(), betamodels.CreateRoleScopeTagCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, tag := range tags {
		r, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement.roleScopeTag",
			map[string]*llx.RawData{
				"__id":        llx.StringDataPtr(tag.GetId()),
				"id":          llx.StringDataPtr(tag.GetId()),
				"displayName": llx.StringDataPtr(tag.GetDisplayName()),
				"description": llx.StringDataPtr(tag.GetDescription()),
				"isBuiltIn":   llx.BoolDataPtr(tag.GetIsBuiltIn()),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}
