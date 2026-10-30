// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"

	abstractions "github.com/microsoft/kiota-abstractions-go"
	"github.com/microsoftgraph/msgraph-sdk-go/groups"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlMicrosoftGroup) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlMicrosoftGroup) members() ([]any, error) {
	msResource, err := a.MqlRuntime.CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	mqlMicrosoftResource := msResource.(*mqlMicrosoft)

	groupId := a.Id.Data
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	top := int32(999)

	// Pull the same fields the rest of the user resource consumes so
	// accessing member.displayName/mail/userPrincipalName is served from
	// this single response instead of triggering initMicrosoftUser per
	// member.
	queryParams := &groups.ItemMembersRequestBuilderGetQueryParameters{
		Top:    &top,
		Select: userSelectFields,
	}
	ctx := context.Background()
	resp, err := graphClient.Groups().
		ByGroupId(groupId).
		Members().
		Get(ctx, &groups.ItemMembersRequestBuilderGetRequestConfiguration{
			QueryParameters: queryParams,
		})
	if err != nil {
		return nil, transformError(err)
	}
	members, err := iterate[models.DirectoryObjectable](ctx, resp, graphClient.GetAdapter(), models.CreateDirectoryObjectCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, member := range members {
		memberId := member.GetId()
		if memberId == nil {
			continue
		}

		if member.GetOdataType() != nil && *member.GetOdataType() != "#microsoft.graph.user" {
			continue
		}

		// if the user is already indexed, we can reuse it
		userResource, ok := mqlMicrosoftResource.userById(*memberId)
		if ok {
			res = append(res, userResource)
			continue
		}

		// When the member is a user, build it from the data already on the
		// response — avoids a second Graph round-trip via initMicrosoftUser.
		if user, ok := member.(models.Userable); ok {
			newUser, err := newMqlMicrosoftUser(a.MqlRuntime, user)
			if err != nil {
				return nil, err
			}
			mqlMicrosoftResource.indexUser(newUser)
			res = append(res, newUser)
			continue
		}

		newUserResource, err := a.MqlRuntime.
			NewResource(a.MqlRuntime, "microsoft.user", map[string]*llx.RawData{
				"id": llx.StringDataPtr(memberId),
			})
		if err != nil {
			return nil, err
		}
		mqlMicrosoftResource.indexUser(newUserResource.(*mqlMicrosoftUser))
		res = append(res, newUserResource)
	}
	return res, nil
}

func (a *mqlMicrosoft) groups() (*mqlMicrosoftGroups, error) {
	mqlResource, err := a.MqlRuntime.CreateResource(a.MqlRuntime, "microsoft.groups", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return mqlResource.(*mqlMicrosoftGroups), err
}

func initMicrosoftGroups(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	args["__id"] = newListResourceIdFromArguments("microsoft.groups", args)
	resource, err := runtime.CreateResource(runtime, "microsoft.groups", args)
	if err != nil {
		return args, nil, err
	}

	return args, resource.(*mqlMicrosoftGroups), nil
}

func (a *mqlMicrosoftGroups) list() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	top := int32(999)
	queryParams := &groups.GroupsRequestBuilderGetQueryParameters{
		Top: &top,
	}
	ctx := context.Background()
	resp, err := graphClient.Groups().Get(ctx, &groups.GroupsRequestBuilderGetRequestConfiguration{
		QueryParameters: queryParams,
	})
	if err != nil {
		return nil, transformError(err)
	}
	grps, err := iterate[*models.Group](ctx, resp, graphClient.GetAdapter(), groups.CreateDeltaGetResponseFromDiscriminatorValue)
	if err != nil {
		return nil, transformError(err)
	}
	res := []any{}
	for _, grp := range grps {
		graphGrp, err := newMqlMicrosoftGroup(a.MqlRuntime, grp)
		if err != nil {
			return nil, err
		}
		res = append(res, graphGrp)
	}

	return res, nil
}

// newMqlMicrosoftGroup builds a microsoft.group resource from a Graph group.
func newMqlMicrosoftGroup(runtime *plugin.Runtime, grp models.Groupable) (*mqlMicrosoftGroup, error) {
	graphGrp, err := CreateResource(runtime, "microsoft.group",
		map[string]*llx.RawData{
			"id":                            llx.StringDataPtr(grp.GetId()),
			"displayName":                   llx.StringDataPtr(grp.GetDisplayName()),
			"mail":                          llx.StringDataPtr(grp.GetMail()),
			"mailEnabled":                   llx.BoolDataPtr(grp.GetMailEnabled()),
			"mailNickname":                  llx.StringDataPtr(grp.GetMailNickname()),
			"securityEnabled":               llx.BoolDataPtr(grp.GetSecurityEnabled()),
			"visibility":                    llx.StringDataPtr(grp.GetVisibility()),
			"groupTypes":                    llx.ArrayData(llx.TArr2Raw(grp.GetGroupTypes()), types.String),
			"membershipRule":                llx.StringDataPtr(grp.GetMembershipRule()),
			"membershipRuleProcessingState": llx.StringDataPtr(grp.GetMembershipRuleProcessingState()),
			"createdDateTime":               graphTimeData(grp.GetCreatedDateTime()),
			"description":                   llx.StringDataPtr(grp.GetDescription()),
			"expirationDateTime":            graphTimeData(grp.GetExpirationDateTime()),
			"isAssignableToRole":            llx.BoolDataPtr(grp.GetIsAssignableToRole()),
			"renewedDateTime":               graphTimeData(grp.GetRenewedDateTime()),
			"onPremisesSyncEnabled":         llx.BoolDataPtr(grp.GetOnPremisesSyncEnabled()),
			"onPremisesLastSyncDateTime":    graphTimeData(grp.GetOnPremisesLastSyncDateTime()),
			"classification":                llx.StringDataPtr(grp.GetClassification()),
			"deletedDateTime":               graphTimeData(grp.GetDeletedDateTime()),
			"proxyAddresses":                llx.ArrayData(llx.TArr2Raw(grp.GetProxyAddresses()), types.String),
			"theme":                         llx.StringDataPtr(grp.GetTheme()),
			"preferredLanguage":             llx.StringDataPtr(grp.GetPreferredLanguage()),
			"preferredDataLocation":         llx.StringDataPtr(grp.GetPreferredDataLocation()),
		})
	if err != nil {
		return nil, err
	}
	return graphGrp.(*mqlMicrosoftGroup), nil
}

// initMicrosoftGroup resolves a single group by its object ID, enabling
// microsoft.group(id: "...") lookups and typed group references.
func initMicrosoftGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// only resolve when handed a bare id; a fully populated group passes
	// through untouched
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
	grp, err := graphClient.Groups().ByGroupId(rawId.Value.(string)).Get(ctx, nil)
	if err != nil {
		return nil, nil, transformError(err)
	}

	mqlGroup, err := newMqlMicrosoftGroup(runtime, grp)
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlGroup, nil
}

func (a *mqlMicrosoftGroup) owners() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	groupId := a.Id.Data
	ctx := context.Background()

	ownersResp, err := graphClient.Groups().
		ByGroupId(groupId).
		Owners().
		Get(ctx, &groups.ItemOwnersRequestBuilderGetRequestConfiguration{})
	if err != nil {
		return nil, transformError(err)
	}
	allOwners, err := iterate[models.DirectoryObjectable](ctx, ownersResp, graphClient.GetAdapter(), models.CreateDirectoryObjectCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	var owners []any
	for _, owner := range allOwners {
		if owner.GetId() == nil {
			continue
		}

		var displayName *string

		if owner.GetOdataType() != nil {
			switch *owner.GetOdataType() {
			case "#microsoft.graph.user":
				if user, ok := owner.(models.Userable); ok {
					displayName = user.GetDisplayName()
				}
			case "#microsoft.graph.servicePrincipal":
				if sp, ok := owner.(models.ServicePrincipalable); ok {
					displayName = sp.GetDisplayName()
				}
			}
		}

		ownerResource, err := CreateResource(a.MqlRuntime, ResourceMicrosoftGroupOwner,
			map[string]*llx.RawData{
				"__id":        llx.StringDataPtr(owner.GetId()),
				"id":          llx.StringDataPtr(owner.GetId()),
				"displayName": llx.StringDataPtr(displayName),
				"ownerType":   llx.StringDataPtr(normalizeOwnerType(owner.GetOdataType())),
			})
		if err != nil {
			return nil, err
		}
		owners = append(owners, ownerResource)
	}

	return owners, nil
}

// normalizeOwnerType converts a raw Graph OData type (e.g.
// "#microsoft.graph.user") to the documented short form ("user",
// "servicePrincipal"). Returns nil for a nil input.
func normalizeOwnerType(odataType *string) *string {
	if odataType == nil {
		return nil
	}
	short := strings.TrimPrefix(*odataType, "#microsoft.graph.")
	return &short
}

func (a *mqlMicrosoftGroupOwner) user() (*mqlMicrosoftUser, error) {
	if a.OwnerType.Data != "user" {
		// This owner is a service principal (or other type); the user ref is
		// legitimately absent. Mark it null so callers can select user() and
		// servicePrincipal() side by side without erroring the whole query.
		a.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	userId := a.Id.Data
	userResource, err := a.MqlRuntime.NewResource(a.MqlRuntime, ResourceMicrosoftUser,
		map[string]*llx.RawData{
			"id": llx.StringData(userId),
		})
	if err != nil {
		return nil, err
	}
	return userResource.(*mqlMicrosoftUser), nil
}

func (a *mqlMicrosoftGroupOwner) servicePrincipal() (*mqlMicrosoftServiceprincipal, error) {
	if a.OwnerType.Data != "servicePrincipal" {
		// This owner is a user (or other type); the service principal ref is
		// legitimately absent. Mark it null so callers can select user() and
		// servicePrincipal() side by side without erroring the whole query.
		a.ServicePrincipal.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	spId := a.Id.Data
	spResource, err := a.MqlRuntime.NewResource(a.MqlRuntime, ResourceMicrosoftServiceprincipal,
		map[string]*llx.RawData{
			"id": llx.StringData(spId),
		})
	if err != nil {
		return nil, err
	}
	return spResource.(*mqlMicrosoftServiceprincipal), nil
}

func (a *mqlMicrosoftGroups) count() (int64, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return 0, err
	}

	opts := &groups.CountRequestBuilderGetRequestConfiguration{Headers: abstractions.NewRequestHeaders()}
	opts.Headers.Add("ConsistencyLevel", "eventual")
	count, err := graphClient.Groups().Count().Get(context.Background(), opts)
	if err != nil {
		return 0, err
	}
	if count == nil {
		// This should never happen, but we better check
		return 0, errors.New("unable to count groups, counter parameter API returned nil")
	}

	return int64(*count), nil
}
