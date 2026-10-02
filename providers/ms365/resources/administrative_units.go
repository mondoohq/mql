// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/directory"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

var administrativeUnitSelectFields = []string{
	"id",
	"displayName",
	"description",
	"visibility",
	"isMemberManagementRestricted",
	"membershipType",
	"membershipRule",
	"membershipRuleProcessingState",
}

func (a *mqlMicrosoft) administrativeUnits() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	top := int32(999)
	resp, err := graphClient.Directory().AdministrativeUnits().Get(ctx, &directory.AdministrativeUnitsRequestBuilderGetRequestConfiguration{
		QueryParameters: &directory.AdministrativeUnitsRequestBuilderGetQueryParameters{
			Top:    &top,
			Select: administrativeUnitSelectFields,
		},
	})
	if err != nil {
		return nil, transformError(err)
	}
	units, err := iterate[models.AdministrativeUnitable](ctx, resp, graphClient.GetAdapter(), models.CreateAdministrativeUnitCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, transformError(err)
	}

	res := []any{}
	for _, unit := range units {
		if unit == nil || unit.GetId() == nil {
			continue
		}
		mqlUnit, err := CreateResource(a.MqlRuntime, ResourceMicrosoftAdministrativeUnit, administrativeUnitArgs(unit))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlUnit)
	}
	return res, nil
}

// administrativeUnitArgs maps a Graph administrative unit onto the resource's
// fields.
func administrativeUnitArgs(unit models.AdministrativeUnitable) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                          llx.StringDataPtr(unit.GetId()),
		"id":                            llx.StringDataPtr(unit.GetId()),
		"displayName":                   llx.StringDataPtr(unit.GetDisplayName()),
		"description":                   llx.StringDataPtr(unit.GetDescription()),
		"visibility":                    llx.StringDataPtr(unit.GetVisibility()),
		"isMemberManagementRestricted":  llx.BoolDataPtr(unit.GetIsMemberManagementRestricted()),
		"membershipType":                llx.StringDataPtr(unit.GetMembershipType()),
		"membershipRule":                llx.StringDataPtr(unit.GetMembershipRule()),
		"membershipRuleProcessingState": llx.StringDataPtr(unit.GetMembershipRuleProcessingState()),
	}
}

func (a *mqlMicrosoftAdministrativeUnit) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlMicrosoftAdministrativeUnit) members() ([]any, error) {
	msResource, err := a.MqlRuntime.CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	mqlMicrosoftResource := msResource.(*mqlMicrosoft)

	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	top := int32(999)
	// The user cast segment returns only user members, with the same fields
	// the user resource reads elsewhere, so no member needs a second lookup.
	resp, err := graphClient.Directory().AdministrativeUnits().ByAdministrativeUnitId(a.Id.Data).
		Members().GraphUser().
		Get(ctx, &directory.AdministrativeUnitsItemMembersGraphUserRequestBuilderGetRequestConfiguration{
			QueryParameters: &directory.AdministrativeUnitsItemMembersGraphUserRequestBuilderGetQueryParameters{
				Top:    &top,
				Select: userSelectFields,
			},
		})
	if err != nil {
		return nil, transformError(err)
	}
	users, err := iterate[models.Userable](ctx, resp, graphClient.GetAdapter(), models.CreateUserCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, transformError(err)
	}

	res := []any{}
	for _, user := range users {
		if user == nil || user.GetId() == nil {
			continue
		}
		if existing, ok := mqlMicrosoftResource.userById(*user.GetId()); ok {
			res = append(res, existing)
			continue
		}
		mqlUser, err := newMqlMicrosoftUser(a.MqlRuntime, user)
		if err != nil {
			return nil, err
		}
		mqlMicrosoftResource.indexUser(mqlUser)
		res = append(res, mqlUser)
	}
	return res, nil
}

func (a *mqlMicrosoftAdministrativeUnit) memberGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	top := int32(999)
	resp, err := graphClient.Directory().AdministrativeUnits().ByAdministrativeUnitId(a.Id.Data).
		Members().GraphGroup().
		Get(ctx, &directory.AdministrativeUnitsItemMembersGraphGroupRequestBuilderGetRequestConfiguration{
			QueryParameters: &directory.AdministrativeUnitsItemMembersGraphGroupRequestBuilderGetQueryParameters{
				Top: &top,
			},
		})
	if err != nil {
		return nil, transformError(err)
	}
	groups, err := iterate[models.Groupable](ctx, resp, graphClient.GetAdapter(), models.CreateGroupCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, transformError(err)
	}

	res := []any{}
	for _, grp := range groups {
		if grp == nil || grp.GetId() == nil {
			continue
		}
		mqlGroup, err := newMqlMicrosoftGroup(a.MqlRuntime, grp)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGroup)
	}
	return res, nil
}

func (a *mqlMicrosoftAdministrativeUnit) memberDevices() ([]any, error) {
	msResource, err := a.MqlRuntime.CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	mqlMicrosoftResource := msResource.(*mqlMicrosoft)

	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	top := int32(999)
	resp, err := graphClient.Directory().AdministrativeUnits().ByAdministrativeUnitId(a.Id.Data).
		Members().GraphDevice().
		Get(ctx, &directory.AdministrativeUnitsItemMembersGraphDeviceRequestBuilderGetRequestConfiguration{
			QueryParameters: &directory.AdministrativeUnitsItemMembersGraphDeviceRequestBuilderGetQueryParameters{
				Top:    &top,
				Select: deviceSelectFields,
			},
		})
	if err != nil {
		return nil, transformError(err)
	}
	devices, err := iterate[models.Deviceable](ctx, resp, graphClient.GetAdapter(), models.CreateDeviceCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, transformError(err)
	}

	res := []any{}
	for _, device := range devices {
		if device == nil || device.GetId() == nil {
			continue
		}
		if existing, ok := mqlMicrosoftResource.deviceById(*device.GetId()); ok {
			res = append(res, existing)
			continue
		}
		mqlDevice, err := newMqlMicrosoftDevice(a.MqlRuntime, device)
		if err != nil {
			return nil, err
		}
		mqlMicrosoftResource.indexDevice(mqlDevice)
		res = append(res, mqlDevice)
	}
	return res, nil
}

func (a *mqlMicrosoftAdministrativeUnit) scopedRoleMembers() ([]any, error) {
	msResource, err := a.MqlRuntime.CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	mqlMicrosoftResource := msResource.(*mqlMicrosoft)

	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	top := int32(999)
	resp, err := graphClient.Directory().AdministrativeUnits().ByAdministrativeUnitId(a.Id.Data).
		ScopedRoleMembers().
		Get(ctx, &directory.AdministrativeUnitsItemScopedRoleMembersRequestBuilderGetRequestConfiguration{
			QueryParameters: &directory.AdministrativeUnitsItemScopedRoleMembersRequestBuilderGetQueryParameters{
				Top: &top,
			},
		})
	if err != nil {
		return nil, transformError(err)
	}
	memberships, err := iterate[models.ScopedRoleMembershipable](ctx, resp, graphClient.GetAdapter(), models.CreateScopedRoleMembershipCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, transformError(err)
	}
	if len(memberships) == 0 {
		return []any{}, nil
	}

	// roleId names the activated directory role, not its definition. The
	// tenant's directory roles are read once and map each to its template,
	// which is the id of the matching role definition.
	roleTemplates, err := mqlMicrosoftResource.directoryRoleTemplates(ctx, graphClient)
	if err != nil {
		return nil, err
	}

	// roleMemberInfo carries no object type, so the principals are read in
	// one bulk request to tell users, groups, and service principals apart.
	principalIds := []string{}
	for _, m := range memberships {
		if id := scopedRoleMemberPrincipalId(m); id != "" {
			principalIds = append(principalIds, id)
		}
	}
	principals, err := fetchDirectoryObjectsByIds(ctx, graphClient, principalIds)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, m := range memberships {
		if m == nil || m.GetId() == nil {
			continue
		}
		var displayName *string
		if info := m.GetRoleMemberInfo(); info != nil {
			displayName = info.GetDisplayName()
		}
		principalId := scopedRoleMemberPrincipalId(m)
		principalType := directoryObjectShortType(principals[principalId])

		mqlResource, err := CreateResource(a.MqlRuntime, ResourceMicrosoftAdministrativeUnitScopedRoleMember,
			map[string]*llx.RawData{
				"__id":                 llx.StringData(a.Id.Data + "/" + *m.GetId()),
				"id":                   llx.StringDataPtr(m.GetId()),
				"principalDisplayName": llx.StringDataPtr(displayName),
				"principalType":        llx.StringData(principalType),
			})
		if err != nil {
			return nil, err
		}
		member := mqlResource.(*mqlMicrosoftAdministrativeUnitScopedRoleMember)
		member.cachePrincipalId = principalId
		if roleId := m.GetRoleId(); roleId != nil {
			member.cacheRoleDefinitionId = roleTemplates[*roleId]
		}
		res = append(res, member)
	}
	return res, nil
}

// scopedRoleMemberPrincipalId returns the directory object id of the
// principal holding a scoped role membership, or "" when Graph omits it.
func scopedRoleMemberPrincipalId(m models.ScopedRoleMembershipable) string {
	if m == nil {
		return ""
	}
	info := m.GetRoleMemberInfo()
	if info == nil || info.GetId() == nil {
		return ""
	}
	return *info.GetId()
}

// directoryObjectShortType returns the short directory type of an object
// ("user", "group", "servicePrincipal"), or "" when the object is nil or
// carries no type.
func directoryObjectShortType(obj models.DirectoryObjectable) string {
	if obj == nil {
		return ""
	}
	short := normalizeOwnerType(obj.GetOdataType())
	if short == nil {
		return ""
	}
	return *short
}

// directoryRoleTemplateIds maps each directory role's object id to its
// roleTemplateId. Roles without either id are left out.
func directoryRoleTemplateIds(roles []models.DirectoryRoleable) map[string]string {
	res := make(map[string]string, len(roles))
	for _, role := range roles {
		if role == nil || role.GetId() == nil || role.GetRoleTemplateId() == nil {
			continue
		}
		res[*role.GetId()] = *role.GetRoleTemplateId()
	}
	return res
}

// directoryRoleTemplateCache holds the tenant's directory role to template
// mapping, read once for every administrative unit.
type directoryRoleTemplateCache struct {
	once sync.Once
	data map[string]string
	err  error
}

// directoryRoleTemplates returns the directory role id to role template id
// mapping for the tenant, reading /directoryRoles on first use.
func (a *mqlMicrosoft) directoryRoleTemplates(ctx context.Context, graphClient *msgraphsdkgo.GraphServiceClient) (map[string]string, error) {
	c := &a.dirRoleTemplates
	c.once.Do(func() {
		resp, err := graphClient.DirectoryRoles().Get(ctx, nil)
		if err != nil {
			c.err = transformError(err)
			return
		}
		roles, err := iterate[models.DirectoryRoleable](ctx, resp, graphClient.GetAdapter(), models.CreateDirectoryRoleCollectionResponseFromDiscriminatorValue)
		if err != nil {
			c.err = transformError(err)
			return
		}
		c.data = directoryRoleTemplateIds(roles)
	})
	return c.data, c.err
}

type mqlMicrosoftAdministrativeUnitScopedRoleMemberInternal struct {
	cachePrincipalId      string
	cacheRoleDefinitionId string
}

func (a *mqlMicrosoftAdministrativeUnitScopedRoleMember) role() (*mqlMicrosoftRolemanagementRoledefinition, error) {
	if a.cacheRoleDefinitionId == "" {
		a.Role.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceMicrosoftRolemanagementRoledefinition, map[string]*llx.RawData{
		"id": llx.StringData(a.cacheRoleDefinitionId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftRolemanagementRoledefinition), nil
}

func (a *mqlMicrosoftAdministrativeUnitScopedRoleMember) user() (*mqlMicrosoftUser, error) {
	if a.PrincipalType.Data != "user" || a.cachePrincipalId == "" {
		a.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	msResource, err := a.MqlRuntime.CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	if existing, ok := msResource.(*mqlMicrosoft).userById(a.cachePrincipalId); ok {
		return existing, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceMicrosoftUser, map[string]*llx.RawData{
		"id": llx.StringData(a.cachePrincipalId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftUser), nil
}

func (a *mqlMicrosoftAdministrativeUnitScopedRoleMember) group() (*mqlMicrosoftGroup, error) {
	if a.PrincipalType.Data != "group" || a.cachePrincipalId == "" {
		a.Group.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceMicrosoftGroup, map[string]*llx.RawData{
		"id": llx.StringData(a.cachePrincipalId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftGroup), nil
}

func (a *mqlMicrosoftAdministrativeUnitScopedRoleMember) servicePrincipal() (*mqlMicrosoftServiceprincipal, error) {
	if a.PrincipalType.Data != "servicePrincipal" || a.cachePrincipalId == "" {
		a.ServicePrincipal.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceMicrosoftServiceprincipal, map[string]*llx.RawData{
		"id": llx.StringData(a.cachePrincipalId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoftServiceprincipal), nil
}
