// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

const (
	permRoleAssignmentScheduleRead = "RoleAssignmentSchedule.Read.Directory"
	permPrivilegedAssignmentGroup  = "PrivilegedAssignmentSchedule.Read.AzureADGroup"
	permPrivilegedEligibilityGroup = "PrivilegedEligibilitySchedule.Read.AzureADGroup"
	permDirectoryRead              = "Directory.Read.All"
)

// isPremiumLicenseRequired reports whether Graph refused the request because
// the tenant lacks the Microsoft Entra ID P2 (or Governance) license PIM needs.
func isPremiumLicenseRequired(err error) bool {
	return graphErrorCode(err) == "AadPremiumLicenseRequired"
}

// classifyPimError turns a refused PIM request into a classified error: a
// tenant without the license PIM needs is NotApplicable, and anything else
// goes through classifyGraphError, which names the permission on a 403.
func classifyPimError(err error, permissions ...string) error {
	if err == nil {
		return nil
	}
	if isPremiumLicenseRequired(err) {
		return llx.NotApplicable(transformError(err))
	}
	return classifyGraphError(err, permissions...)
}

// principalTypesByID reads the directory type (user, group, servicePrincipal)
// of each principal in one bulk request. A principal that no longer exists is
// absent from the result.
func principalTypesByID(ctx context.Context, graphClient *msgraphsdkgo.GraphServiceClient, ids []string) (map[string]string, error) {
	unique := uniqueNonEmpty(ids)
	res := make(map[string]string, len(unique))
	if len(unique) == 0 {
		return res, nil
	}
	objs, err := fetchDirectoryObjectsByIds(ctx, graphClient, unique)
	if err != nil {
		return nil, classifyPimError(err, permDirectoryRead)
	}
	for id, obj := range objs {
		if t := normalizeOwnerType(obj.GetOdataType()); t != nil {
			res[id] = *t
		}
	}
	return res, nil
}

// uniqueNonEmpty returns ids with empty strings and duplicates removed, in
// first-seen order.
func uniqueNonEmpty(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	res := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		res = append(res, id)
	}
	return res
}

// enumString renders an optional SDK enum, keeping an absent value null.
func enumString[T fmt.Stringer](v *T) *string {
	if v == nil {
		return nil
	}
	s := (*v).String()
	return &s
}

func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// principalOfType resolves a principal reference when the principal is of the
// wanted directory type, and marks the field null otherwise.
func principalOfType[T plugin.Resource](runtime *plugin.Runtime, field *plugin.TValue[T], principalType, wantType, principalID, resource string) (T, error) {
	if principalType != wantType {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		var zero T
		return zero, nil
	}
	return directoryRefByID(runtime, field, principalID, resource)
}

// directoryRefByID resolves a reference to a directory object by its ID, and
// marks the field null when there is no ID.
func directoryRefByID[T plugin.Resource](runtime *plugin.Runtime, field *plugin.TValue[T], id, resource string) (T, error) {
	var zero T
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return zero, nil
	}
	res, err := NewResource(runtime, resource, map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return zero, err
	}
	return res.(T), nil
}

// Least privileged permissions: RoleAssignmentSchedule.Read.Directory
func (a *mqlMicrosoftIdentityAndAccess) roleAssignmentScheduleInstances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.RoleManagement().Directory().RoleAssignmentScheduleInstances().Get(ctx, nil)
	if err != nil {
		return nil, classifyPimError(err, permRoleAssignmentScheduleRead)
	}
	instances, err := iterate[models.UnifiedRoleAssignmentScheduleInstanceable](ctx, resp, graphClient.GetAdapter(), models.CreateUnifiedRoleAssignmentScheduleInstanceCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyPimError(err, permRoleAssignmentScheduleRead)
	}

	principalIDs := make([]string, 0, len(instances))
	for _, inst := range instances {
		principalIDs = append(principalIDs, strVal(inst.GetPrincipalId()))
	}
	principalTypes, err := principalTypesByID(ctx, graphClient, principalIDs)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, inst := range instances {
		if inst.GetId() == nil {
			continue
		}
		r, err := CreateResource(a.MqlRuntime, ResourceMicrosoftIdentityAndAccessRoleAssignmentScheduleInstance, roleAssignmentInstanceArgs(inst, principalTypes))
		if err != nil {
			return nil, err
		}
		mqlInst := r.(*mqlMicrosoftIdentityAndAccessRoleAssignmentScheduleInstance)
		mqlInst.cacheRoleDefinitionID = strVal(inst.GetRoleDefinitionId())
		res = append(res, mqlInst)
	}
	return res, nil
}

// roleAssignmentInstanceArgs maps a directory role assignment schedule
// instance onto the fields of its MQL resource.
func roleAssignmentInstanceArgs(inst models.UnifiedRoleAssignmentScheduleInstanceable, principalTypes map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                     llx.StringDataPtr(inst.GetId()),
		"id":                       llx.StringDataPtr(inst.GetId()),
		"principalId":              llx.StringDataPtr(inst.GetPrincipalId()),
		"principalType":            llx.StringData(principalTypes[strVal(inst.GetPrincipalId())]),
		"directoryScopeId":         llx.StringDataPtr(inst.GetDirectoryScopeId()),
		"appScopeId":               llx.StringDataPtr(inst.GetAppScopeId()),
		"assignmentType":           llx.StringDataPtr(inst.GetAssignmentType()),
		"memberType":               llx.StringDataPtr(inst.GetMemberType()),
		"startDateTime":            graphTimeData(inst.GetStartDateTime()),
		"endDateTime":              graphTimeData(inst.GetEndDateTime()),
		"roleAssignmentOriginId":   llx.StringDataPtr(inst.GetRoleAssignmentOriginId()),
		"roleAssignmentScheduleId": llx.StringDataPtr(inst.GetRoleAssignmentScheduleId()),
	}
}

type mqlMicrosoftIdentityAndAccessRoleAssignmentScheduleInstanceInternal struct {
	cacheRoleDefinitionID string
}

func (a *mqlMicrosoftIdentityAndAccessRoleAssignmentScheduleInstance) roleDefinition() (*mqlMicrosoftRolemanagementRoledefinition, error) {
	if a.cacheRoleDefinitionID == "" {
		a.RoleDefinition.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "microsoft.rolemanagement.roledefinition", map[string]*llx.RawData{
		"id": llx.StringData(a.cacheRoleDefinitionID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftRolemanagementRoledefinition), nil
}

func (a *mqlMicrosoftIdentityAndAccessRoleAssignmentScheduleInstance) principalUser() (*mqlMicrosoftUser, error) {
	return principalOfType(a.MqlRuntime, &a.PrincipalUser, a.PrincipalType.Data, "user", a.PrincipalId.Data, ResourceMicrosoftUser)
}

func (a *mqlMicrosoftIdentityAndAccessRoleAssignmentScheduleInstance) principalGroup() (*mqlMicrosoftGroup, error) {
	return principalOfType(a.MqlRuntime, &a.PrincipalGroup, a.PrincipalType.Data, "group", a.PrincipalId.Data, ResourceMicrosoftGroup)
}

func (a *mqlMicrosoftIdentityAndAccessRoleAssignmentScheduleInstance) principalServicePrincipal() (*mqlMicrosoftServiceprincipal, error) {
	return principalOfType(a.MqlRuntime, &a.PrincipalServicePrincipal, a.PrincipalType.Data, "servicePrincipal", a.PrincipalId.Data, ResourceMicrosoftServiceprincipal)
}
