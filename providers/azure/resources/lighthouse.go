// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managedservices/armmanagedservices"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionLighthouseServiceRegistrationDefinitionInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionLighthouseServiceRegistrationDefinitionAuthorizationInternal struct {
	cacheSubId string
}

type mqlAzureSubscriptionLighthouseServiceRegistrationAssignmentInternal struct {
	cacheSystemData               any
	cacheRegistrationDefinitionId string
}

func initAzureSubscriptionLighthouseService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	args["subscriptionId"] = llx.StringData(conn.SubId())

	return args, nil, nil
}

func (a *mqlAzureSubscriptionLighthouseService) id() (string, error) {
	return "azure.subscription.lighthouseService/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionLighthouseServiceRegistrationDefinition) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionLighthouseServiceRegistrationAssignment) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionLighthouseService) registrationDefinitions() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	subId := a.SubscriptionId.Data

	ctx := context.Background()
	client, err := armmanagedservices.NewRegistrationDefinitionsClient(conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	scope := fmt.Sprintf("/subscriptions/%s", subId)
	pager := client.NewListPager(scope, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list lighthouse registration definitions due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, def := range page.Value {
			if def == nil {
				continue
			}
			mqlDef, err := lighthouseRegistrationDefinitionToMql(a.MqlRuntime, subId, def)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDef)
		}
	}
	return res, nil
}

func lighthouseRegistrationDefinitionToMql(runtime *plugin.Runtime, subId string, def *armmanagedservices.RegistrationDefinition) (*mqlAzureSubscriptionLighthouseServiceRegistrationDefinition, error) {
	defId := convert.ToValue(def.ID)

	authorizations := []any{}
	eligibleAuthorizations := []any{}
	var managedByTenantId, managedByTenantName, displayName, description, provisioningState string
	if props := def.Properties; props != nil {
		managedByTenantId = convert.ToValue(props.ManagedByTenantID)
		managedByTenantName = convert.ToValue(props.ManagedByTenantName)
		displayName = convert.ToValue(props.RegistrationDefinitionName)
		description = convert.ToValue(props.Description)
		provisioningState = string(convert.ToValue(props.ProvisioningState))

		for _, auth := range props.Authorizations {
			if auth == nil {
				continue
			}
			mqlAuth, err := lighthouseAuthorizationToMql(runtime, subId, defId, auth.PrincipalID, auth.PrincipalIDDisplayName, auth.RoleDefinitionID, auth.DelegatedRoleDefinitionIDs, false, nil)
			if err != nil {
				return nil, err
			}
			authorizations = append(authorizations, mqlAuth)
		}
		for _, auth := range props.EligibleAuthorizations {
			if auth == nil {
				continue
			}
			mqlAuth, err := lighthouseAuthorizationToMql(runtime, subId, defId, auth.PrincipalID, auth.PrincipalIDDisplayName, auth.RoleDefinitionID, nil, true, auth.JustInTimeAccessPolicy)
			if err != nil {
				return nil, err
			}
			eligibleAuthorizations = append(eligibleAuthorizations, mqlAuth)
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.lighthouseService.registrationDefinition",
		map[string]*llx.RawData{
			"__id":                   llx.StringData(defId),
			"id":                     llx.StringData(defId),
			"name":                   llx.StringDataPtr(def.Name),
			"displayName":            llx.StringData(displayName),
			"description":            llx.StringData(description),
			"managedByTenantId":      llx.StringData(managedByTenantId),
			"managedByTenantName":    llx.StringData(managedByTenantName),
			"provisioningState":      llx.StringData(provisioningState),
			"authorizations":         llx.ArrayData(authorizations, types.Resource("azure.subscription.lighthouseService.registrationDefinition.authorization")),
			"eligibleAuthorizations": llx.ArrayData(eligibleAuthorizations, types.Resource("azure.subscription.lighthouseService.registrationDefinition.authorization")),
		})
	if err != nil {
		return nil, err
	}
	mqlDef := res.(*mqlAzureSubscriptionLighthouseServiceRegistrationDefinition)
	if def.SystemData != nil {
		mqlDef.cacheSystemData, err = convert.JsonToDict(def.SystemData)
		if err != nil {
			return nil, err
		}
	}
	return mqlDef, nil
}

func lighthouseAuthorizationToMql(runtime *plugin.Runtime, subId, defId string, principalID, principalDisplayName, roleDefinitionID *string, delegatedRoleDefinitionIDs []*string, eligible bool, jitPolicy any) (*mqlAzureSubscriptionLighthouseServiceRegistrationDefinitionAuthorization, error) {
	principalId := convert.ToValue(principalID)
	roleDefId := convert.ToValue(roleDefinitionID)

	// A principal can hold the same role both as a standing and an eligible
	// grant, so eligible authorizations carry an "/eligible" suffix to keep the
	// cache key unique.
	idSuffix := "/authorizations/"
	if eligible {
		idSuffix = "/eligibleAuthorizations/"
	}
	authId := defId + idSuffix + principalId + "/" + roleDefId

	delegated := []any{}
	for _, d := range delegatedRoleDefinitionIDs {
		if d != nil {
			delegated = append(delegated, *d)
		}
	}

	jitDict, err := convert.JsonToDict(jitPolicy)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "azure.subscription.lighthouseService.registrationDefinition.authorization",
		map[string]*llx.RawData{
			"__id":                       llx.StringData(authId),
			"principalId":                llx.StringData(principalId),
			"principalIdDisplayName":     llx.StringData(convert.ToValue(principalDisplayName)),
			"roleDefinitionId":           llx.StringData(roleDefId),
			"delegatedRoleDefinitionIds": llx.ArrayData(delegated, types.String),
			"eligible":                   llx.BoolData(eligible),
			"justInTimeAccessPolicy":     llx.DictData(jitDict),
		})
	if err != nil {
		return nil, err
	}
	mqlAuth := res.(*mqlAzureSubscriptionLighthouseServiceRegistrationDefinitionAuthorization)
	mqlAuth.cacheSubId = subId
	return mqlAuth, nil
}

func (a *mqlAzureSubscriptionLighthouseServiceRegistrationDefinition) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// roleDefinition resolves the granted built-in role. Lighthouse authorizations
// carry the bare role-definition GUID rather than a full resource path, so we
// match on the trailing GUID segment of the subscription's role definitions.
func (a *mqlAzureSubscriptionLighthouseServiceRegistrationDefinitionAuthorization) roleDefinition() (*mqlAzureSubscriptionAuthorizationServiceRoleDefinition, error) {
	if a.RoleDefinitionId.Data == "" || a.cacheSubId == "" {
		a.RoleDefinition.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	wantGuid := lastPathSegment(a.RoleDefinitionId.Data)

	// __id has to be explicit here. A Lighthouse assignment can name a managed
	// customer subscription other than the connected one, and azure.subscription
	// derives its cache key from the `id` field these args do not carry -- so
	// without it the delegated role resolves against whichever subscription
	// happened to populate the shared empty key first.
	r, err := CreateResource(a.MqlRuntime, "azure.subscription", map[string]*llx.RawData{
		"__id":           llx.StringData("/subscriptions/" + a.cacheSubId),
		"subscriptionId": llx.StringData(a.cacheSubId),
	})
	if err != nil {
		return nil, err
	}
	mqlSub := r.(*mqlAzureSubscription)
	iam := mqlSub.GetIam()
	if iam.Error != nil {
		return nil, iam.Error
	}
	roles := iam.Data.GetRoles()
	if roles.Error != nil {
		return nil, roles.Error
	}
	for i := range roles.Data {
		role := roles.Data[i].(*mqlAzureSubscriptionAuthorizationServiceRoleDefinition)
		if lastPathSegment(role.__id) == wantGuid {
			return role, nil
		}
	}

	a.RoleDefinition.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAzureSubscriptionLighthouseService) registrationAssignments() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	subId := a.SubscriptionId.Data

	ctx := context.Background()
	client, err := armmanagedservices.NewRegistrationAssignmentsClient(conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	scope := fmt.Sprintf("/subscriptions/%s", subId)
	pager := client.NewListPager(scope, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list lighthouse registration assignments due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, assignment := range page.Value {
			if assignment == nil {
				continue
			}
			mqlAssignment, err := lighthouseRegistrationAssignmentToMql(a.MqlRuntime, assignment)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAssignment)
		}
	}
	return res, nil
}

func lighthouseRegistrationAssignmentToMql(runtime *plugin.Runtime, assignment *armmanagedservices.RegistrationAssignment) (*mqlAzureSubscriptionLighthouseServiceRegistrationAssignment, error) {
	assignmentId := convert.ToValue(assignment.ID)

	var registrationDefinitionId, provisioningState string
	if props := assignment.Properties; props != nil {
		registrationDefinitionId = convert.ToValue(props.RegistrationDefinitionID)
		provisioningState = string(convert.ToValue(props.ProvisioningState))
	}

	res, err := CreateResource(runtime, "azure.subscription.lighthouseService.registrationAssignment",
		map[string]*llx.RawData{
			"__id":              llx.StringData(assignmentId),
			"id":                llx.StringData(assignmentId),
			"name":              llx.StringDataPtr(assignment.Name),
			"scope":             llx.StringData(assignmentScope(assignmentId)),
			"provisioningState": llx.StringData(provisioningState),
		})
	if err != nil {
		return nil, err
	}
	mqlAssignment := res.(*mqlAzureSubscriptionLighthouseServiceRegistrationAssignment)
	mqlAssignment.cacheRegistrationDefinitionId = registrationDefinitionId
	if assignment.SystemData != nil {
		mqlAssignment.cacheSystemData, err = convert.JsonToDict(assignment.SystemData)
		if err != nil {
			return nil, err
		}
	}
	return mqlAssignment, nil
}

func (a *mqlAzureSubscriptionLighthouseServiceRegistrationAssignment) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionLighthouseServiceRegistrationAssignment) registrationDefinition() (*mqlAzureSubscriptionLighthouseServiceRegistrationDefinition, error) {
	if a.cacheRegistrationDefinitionId == "" {
		a.RegistrationDefinition.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	subId, err := extractSubscriptionID(a.Id.Data)
	if err != nil {
		a.RegistrationDefinition.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	r, err := CreateResource(a.MqlRuntime, "azure.subscription", map[string]*llx.RawData{
		"__id":           llx.StringData("/subscriptions/" + subId),
		"subscriptionId": llx.StringData(subId),
	})
	if err != nil {
		return nil, err
	}
	mqlSub := r.(*mqlAzureSubscription)
	lighthouse := mqlSub.GetLighthouse()
	if lighthouse.Error != nil {
		return nil, lighthouse.Error
	}
	definitions := lighthouse.Data.GetRegistrationDefinitions()
	if definitions.Error != nil {
		return nil, definitions.Error
	}
	for i := range definitions.Data {
		def := definitions.Data[i].(*mqlAzureSubscriptionLighthouseServiceRegistrationDefinition)
		if def.__id == a.cacheRegistrationDefinitionId {
			return def, nil
		}
	}

	a.RegistrationDefinition.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func lastPathSegment(s string) string {
	_, after, ok := strings.CutLast(s, "/")
	if !ok {
		return s
	}
	return after
}

// assignmentScope returns the delegated scope an assignment applies to by
// trimming the Microsoft.ManagedServices resource-provider suffix from the
// assignment's resource ID.
func assignmentScope(assignmentId string) string {
	if before, _, ok := strings.Cut(assignmentId, "/providers/Microsoft.ManagedServices"); ok {
		return before
	}
	return assignmentId
}
