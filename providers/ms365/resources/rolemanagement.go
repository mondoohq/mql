// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"

	abstractions "github.com/microsoft/kiota-abstractions-go"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/directoryobjects"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/rolemanagement"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

var roledefinitionsSelectFields = []string{
	"id",
	"description",
	"displayName",
	"isBuiltIn",
	"isEnabled",
	"rolePermissions",
	"templateId",
	"version",
}

func (a *mqlMicrosoftRoles) list() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	opts := &rolemanagement.DirectoryRoleDefinitionsRequestBuilderGetRequestConfiguration{
		QueryParameters: &rolemanagement.DirectoryRoleDefinitionsRequestBuilderGetQueryParameters{
			Select: roledefinitionsSelectFields,
		},
	}

	if a.Search.State == plugin.StateIsSet || a.Filter.State == plugin.StateIsSet {
		// search and filter requires this header
		headers := abstractions.NewRequestHeaders()
		headers.Add("ConsistencyLevel", "eventual")
		opts.Headers = headers

		if a.Search.State == plugin.StateIsSet {
			log.Debug().
				Str("search", a.Search.Data).
				Msg("microsoft.roles.list.search set")
			search, err := parseSearch(a.Search.Data)
			if err != nil {
				return nil, err
			}
			opts.QueryParameters.Search = &search
		}
		if a.Filter.State == plugin.StateIsSet {
			log.Debug().
				Str("filter", a.Filter.Data).
				Msg("microsoft.roles.list.filter set")
			opts.QueryParameters.Filter = &a.Filter.Data
			count := true
			opts.QueryParameters.Count = &count
		}
	}

	resp, err := graphClient.
		RoleManagement().
		Directory().
		RoleDefinitions().
		Get(ctx, opts)
	if err != nil {
		return nil, transformError(err)
	}
	roles, err := iterate[models.UnifiedRoleDefinitionable](ctx, resp, graphClient.GetAdapter(), models.CreateUnifiedRoleDefinitionCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, role := range roles {
		mqlResource, err := newMqlMicrosoftRoleDefinition(a.MqlRuntime, role)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlResource)
	}

	return res, nil
}

// newMqlMicrosoftRoleDefinition builds a microsoft.rolemanagement.roledefinition
// resource from a Graph unified role definition.
func newMqlMicrosoftRoleDefinition(runtime *plugin.Runtime, role models.UnifiedRoleDefinitionable) (*mqlMicrosoftRolemanagementRoledefinition, error) {
	rolePermissions, err := convert.JsonToDictSlice(newUnifiedRolePermissions(role.GetRolePermissions()))
	if err != nil {
		return nil, err
	}
	mqlResource, err := CreateResource(runtime, "microsoft.rolemanagement.roledefinition",
		map[string]*llx.RawData{
			"id":              llx.StringDataPtr(role.GetId()),
			"description":     llx.StringDataPtr(role.GetDescription()),
			"displayName":     llx.StringDataPtr(role.GetDisplayName()),
			"isBuiltIn":       llx.BoolDataPtr(role.GetIsBuiltIn()),
			"isEnabled":       llx.BoolDataPtr(role.GetIsEnabled()),
			"rolePermissions": llx.ArrayData(rolePermissions, types.Any),
			"templateId":      llx.StringDataPtr(role.GetTemplateId()),
			"version":         llx.StringDataPtr(role.GetVersion()),
		})
	if err != nil {
		return nil, err
	}
	return mqlResource.(*mqlMicrosoftRolemanagementRoledefinition), nil
}

// initMicrosoftRolemanagementRoledefinition resolves a single role definition
// by its ID, enabling typed role references from Conditional Access conditions
// and role assignments.
func initMicrosoftRolemanagementRoledefinition(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// only resolve when handed a bare id; a fully populated role definition
	// passes through untouched
	if len(args) != 1 {
		return args, nil, nil
	}
	rawId, ok := args["id"]
	if !ok {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	role, err := graphClient.
		RoleManagement().
		Directory().
		RoleDefinitions().
		ByUnifiedRoleDefinitionId(rawId.Value.(string)).
		Get(ctx, nil)
	if err != nil {
		return nil, nil, transformError(err)
	}

	mqlRole, err := newMqlMicrosoftRoleDefinition(runtime, role)
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlRole, nil
}

func (a *mqlMicrosoft) roles() (*mqlMicrosoftRoles, error) {
	resource, err := a.MqlRuntime.CreateResource(a.MqlRuntime, "microsoft.roles", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}

	return resource.(*mqlMicrosoftRoles), nil
}

func initMicrosoftRoles(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	args["__id"] = newListResourceIdFromArguments("microsoft.roles", args)
	resource, err := runtime.CreateResource(runtime, "microsoft.roles", args)
	if err != nil {
		return args, nil, err
	}

	return args, resource.(*mqlMicrosoftRoles), nil
}

func (m *mqlMicrosoftRolemanagementRoledefinition) id() (string, error) {
	return m.Id.Data, nil
}

// Deprecated: use mqlMicrosoft roles() instead
func (m *mqlMicrosoftRolemanagementRoleassignment) id() (string, error) {
	return m.Id.Data, nil
}

type mqlMicrosoftRolemanagementRoleassignmentInternal struct {
	cacheRoleDefinitionID string
}

// roleDefinition resolves the role definition this assignment grants.
func (m *mqlMicrosoftRolemanagementRoleassignment) roleDefinition() (*mqlMicrosoftRolemanagementRoledefinition, error) {
	id := m.cacheRoleDefinitionID
	if id == "" {
		m.RoleDefinition.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(m.MqlRuntime, "microsoft.rolemanagement.roledefinition", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftRolemanagementRoledefinition), nil
}

// Deprecated: use mqlMicrosoft roles() instead
func (a *mqlMicrosoftRolemanagement) roleDefinitions() (*mqlMicrosoftRoles, error) {
	resource, err := a.MqlRuntime.CreateResource(a.MqlRuntime, "microsoft.roles", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}

	return resource.(*mqlMicrosoftRoles), nil
}

func (a *mqlMicrosoftRolemanagementRoledefinition) assignments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	rows, err := fetchRoleDefinitionAssignments(context.Background(), graphClient, a.Id.Data)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, row := range rows {
		roleAssignment := row.assignment
		directoryPrincipal := row.principal
		principal, err := convert.JsonToDict(newDirectoryPrincipal(directoryPrincipal))
		if err != nil {
			return nil, err
		}
		principalType, principalName := directoryPrincipalInfo(directoryPrincipal)
		mqlResource, err := CreateResource(a.MqlRuntime, "microsoft.rolemanagement.roleassignment",
			map[string]*llx.RawData{
				"id":            llx.StringDataPtr(roleAssignment.GetId()),
				"principalId":   llx.StringDataPtr(roleAssignment.GetPrincipalId()),
				"principalType": llx.StringData(principalType),
				"principalName": llx.StringData(principalName),
				"principal":     llx.DictData(principal),
			})
		if err != nil {
			return nil, err
		}
		mqlRoleAssignment := mqlResource.(*mqlMicrosoftRolemanagementRoleassignment)
		if roleDefinitionID := roleAssignment.GetRoleDefinitionId(); roleDefinitionID != nil {
			mqlRoleAssignment.cacheRoleDefinitionID = *roleDefinitionID
		}
		res = append(res, mqlRoleAssignment)
	}
	return res, nil
}

// roleAssignmentRow is one role assignment with its principal, which is nil
// when the principal no longer exists in the directory.
type roleAssignmentRow struct {
	assignment models.UnifiedRoleAssignmentable
	principal  models.DirectoryObjectable
}

// fetchRoleDefinitionAssignments lists the assignments of one role definition
// with their principals.
//
// The list is requested with $expand=principal. Graph fails that whole request
// with Request_ResourceNotFound when a single assignment points at a deleted
// principal, so a not-found answer is ambiguous: it can mean one dangling
// assignment hides every live one. The request is repeated without $expand to
// tell the cases apart, and the principals are then read in bulk; a principal
// that is gone is left nil. Only when that second request is also not found
// does the role have no assignments to list: several built-in definitions are
// templates a tenant never instantiates, and roleDefinitions returns them all
// the same.
func fetchRoleDefinitionAssignments(ctx context.Context, graphClient *msgraphsdkgo.GraphServiceClient, roleDefinitionId string) ([]roleAssignmentRow, error) {
	filter := "roleDefinitionId eq '" + roleDefinitionId + "'"
	list := func(expand []string) ([]models.UnifiedRoleAssignmentable, error) {
		resp, err := graphClient.RoleManagement().Directory().RoleAssignments().Get(ctx, &rolemanagement.DirectoryRoleAssignmentsRequestBuilderGetRequestConfiguration{
			QueryParameters: &rolemanagement.DirectoryRoleAssignmentsRequestBuilderGetQueryParameters{
				Filter: &filter,
				Expand: expand,
			},
		})
		if err != nil {
			return nil, err
		}
		return iterate[models.UnifiedRoleAssignmentable](ctx, resp, graphClient.GetAdapter(), models.CreateUnifiedRoleAssignmentCollectionResponseFromDiscriminatorValue)
	}

	assignments, err := list([]string{"principal"})
	if err == nil {
		rows := make([]roleAssignmentRow, 0, len(assignments))
		for _, assignment := range assignments {
			rows = append(rows, roleAssignmentRow{assignment: assignment, principal: assignment.GetPrincipal()})
		}
		return rows, nil
	}
	if !isResourceNotFound(err) {
		return nil, transformError(err)
	}

	assignments, err = list(nil)
	if err != nil {
		if isResourceNotFound(err) {
			log.Debug().
				Str("roleDefinitionId", roleDefinitionId).
				Msg("ms365> role definition has no assignable directory role; reporting no assignments")
			return []roleAssignmentRow{}, nil
		}
		return nil, transformError(err)
	}

	log.Debug().
		Str("roleDefinitionId", roleDefinitionId).
		Msg("ms365> role assignments reference a deleted principal; resolving principals separately")

	principalIds := []string{}
	for _, assignment := range assignments {
		if id := assignment.GetPrincipalId(); id != nil && *id != "" {
			principalIds = append(principalIds, *id)
		}
	}
	principals, err := fetchDirectoryObjectsByIds(ctx, graphClient, principalIds)
	if err != nil {
		return nil, err
	}

	rows := make([]roleAssignmentRow, 0, len(assignments))
	for _, assignment := range assignments {
		row := roleAssignmentRow{assignment: assignment}
		if id := assignment.GetPrincipalId(); id != nil {
			row.principal = principals[*id]
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// directoryObjectsByIdsBatchSize is the most ids directoryObjects/getByIds
// accepts in one request.
const directoryObjectsByIdsBatchSize = 1000

// fetchDirectoryObjectsByIds reads directory objects by id, keyed by id. An id
// that no longer exists is simply absent from the result.
func fetchDirectoryObjectsByIds(ctx context.Context, graphClient *msgraphsdkgo.GraphServiceClient, ids []string) (map[string]models.DirectoryObjectable, error) {
	res := map[string]models.DirectoryObjectable{}
	for start := 0; start < len(ids); start += directoryObjectsByIdsBatchSize {
		end := min(start+directoryObjectsByIdsBatchSize, len(ids))
		body := directoryobjects.NewGetByIdsPostRequestBody()
		body.SetIds(ids[start:end])
		resp, err := graphClient.DirectoryObjects().GetByIds().PostAsGetByIdsPostResponse(ctx, body, nil)
		if err != nil {
			return nil, transformError(err)
		}
		for _, obj := range resp.GetValue() {
			if obj == nil || obj.GetId() == nil {
				continue
			}
			res[*obj.GetId()] = obj
		}
	}
	return res, nil
}
