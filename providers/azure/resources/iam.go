// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	authorization "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// sortedUserAssignedIdentityIDs returns the keys of a UserAssignedIdentities
// map (the ARM resource IDs of the assigned managed identities) in stable
// sorted order. Returns nil when the map is empty.
func sortedUserAssignedIdentityIDs[V any](m map[string]V) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sortedUserAssignedIdentityKeys returns the keys of a UserAssignedIdentities
// map whose values are non-pointer (e.g. the MySQL flexible server SDK uses
// map[string]any) in stable sorted order. Returns nil when the map is empty.
func sortedUserAssignedIdentityKeys[V any](m map[string]V) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// resolveUserAssignedIdentities resolves a set of user-assigned managed
// identity ARM resource IDs into typed managedIdentity resources. The IDs are
// the keys of an SDK UserAssignedIdentities map. The runtime cache short-
// circuits identities already listed by managedIdentities(); others are
// fetched on demand by their init. Returns an empty slice when none are set.
func resolveUserAssignedIdentities(runtime *plugin.Runtime, ids []string) ([]any, error) {
	res := make([]any, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		mqlIdentity, err := NewResource(runtime, "azure.subscription.managedIdentity",
			map[string]*llx.RawData{"__id": llx.StringData(id)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlIdentity)
	}
	return res, nil
}

// newSystemAssignedManagedIdentity represents a resource's system-assigned
// managed identity as a managed-identity resource keyed on its principal ID.
// Unlike a user-assigned identity it has no standalone ARM resource, so it is
// synthesized from the owning resource's ID and the identity's principal (and
// tenant) so the same roleAssignments -> role -> permissions chain can be
// traversed.
//
// When principalID is empty (no system-assigned identity) it marks the caller's
// field null and returns nil, so callers pass their field pointer and do not
// guard separately. This mirrors resolveRoleDefinition.
func newSystemAssignedManagedIdentity(runtime *plugin.Runtime, ownerID, principalID, tenantID string, field *plugin.TValue[*mqlAzureSubscriptionManagedIdentity]) (*mqlAzureSubscriptionManagedIdentity, error) {
	if principalID == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := CreateResource(runtime, "azure.subscription.managedIdentity",
		map[string]*llx.RawData{
			"__id":        llx.StringData(ownerID + "/systemAssignedIdentity"),
			"name":        llx.StringData(""),
			"clientId":    llx.StringData(""),
			"principalId": llx.StringData(principalID),
			"tenantId":    llx.StringData(tenantID),
		})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionManagedIdentity), nil
}

// tenantIDFromIdentityDict extracts the tenantId from a resource's identity dict
// (the managed-identity block Azure returns on a resource), or "" when absent.
func tenantIDFromIdentityDict(identity plugin.TValue[any]) string {
	if id, ok := identity.Data.(map[string]any); ok {
		if t, ok := id["tenantId"].(string); ok {
			return t
		}
	}
	return ""
}

func (a *mqlAzureSubscription) iam() (*mqlAzureSubscriptionAuthorizationService, error) {
	svc, err := NewResource(a.MqlRuntime, "azure.subscription.authorizationService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	authSvc := svc.(*mqlAzureSubscriptionAuthorizationService)
	return authSvc, nil
}

func (a *mqlAzureSubscriptionAuthorizationService) id() (string, error) {
	return "azure.subscription.authorization/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionAuthorizationService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionAuthorizationService) roles() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data
	client, err := authorization.NewRoleDefinitionsClient(token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	// we're interested in subscription-level role definitions, so we scope this to the subscription,
	// on which this connection is running
	scope := fmt.Sprintf("/subscriptions/%s", subId)
	pager := client.NewListPager(scope, &authorization.RoleDefinitionsClientListOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, roleDef := range page.Value {
			if roleDef == nil {
				continue
			}
			// Properties is a nullable pointer that is dereferenced throughout
			// the loop body; normalize to an empty struct to avoid a panic
			// (mirrors newMqlRoleAssignment below).
			props := roleDef.Properties
			if props == nil {
				props = &authorization.RoleDefinitionProperties{}
			}
			roleType := convert.ToValue(props.RoleType)
			scopes := []any{}
			for _, s := range props.AssignableScopes {
				if s != nil {
					scopes = append(scopes, *s)
				}
			}
			mqlRoleDefinition, err := CreateResource(a.MqlRuntime, "azure.subscription.authorizationService.roleDefinition",
				map[string]*llx.RawData{
					"__id":        llx.StringDataPtr(roleDef.ID),
					"id":          llx.StringDataPtr(roleDef.ID),
					"name":        llx.StringDataPtr(props.RoleName),
					"description": llx.StringDataPtr(props.Description),
					"type":        llx.StringData(roleType),
					"scopes":      llx.ArrayData(scopes, types.String),
				})
			if err != nil {
				return nil, err
			}
			mqlRole := mqlRoleDefinition.(*mqlAzureSubscriptionAuthorizationServiceRoleDefinition)
			mqlRole.cachePermissions = props.Permissions
			res = append(res, mqlRole)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionAuthorizationServiceRoleDefinitionInternal struct {
	cachePermissions []*authorization.Permission
}

func (a *mqlAzureSubscriptionAuthorizationServiceRoleDefinition) permissions() ([]any, error) {
	res := []any{}
	for idx, p := range a.cachePermissions {
		if p == nil {
			continue
		}
		id := fmt.Sprintf("%s/azure.subscription.authorizationService.roleDefinition.permission/%d", a.Id.Data, idx)
		permission, err := newMqlRolePermission(a.MqlRuntime, id, p)
		if err != nil {
			return nil, err
		}
		res = append(res, permission)
	}
	return res, nil
}

func newMqlRolePermission(runtime *plugin.Runtime, id string, permission *authorization.Permission) (any, error) {
	allowedActions := []any{}
	deniedActions := []any{}
	allowedDataActions := []any{}
	deniedDataActions := []any{}

	for _, a := range permission.Actions {
		if a != nil {
			allowedActions = append(allowedActions, *a)
		}
	}
	for _, a := range permission.NotActions {
		if a != nil {
			deniedActions = append(deniedActions, *a)
		}
	}
	for _, a := range permission.DataActions {
		if a != nil {
			allowedDataActions = append(allowedDataActions, *a)
		}
	}
	for _, a := range permission.NotDataActions {
		if a != nil {
			deniedDataActions = append(deniedDataActions, *a)
		}
	}

	p, err := CreateResource(runtime, "azure.subscription.authorizationService.roleDefinition.permission",
		map[string]*llx.RawData{
			"__id":               llx.StringData(id),
			"id":                 llx.StringData(id),
			"allowedActions":     llx.ArrayData(allowedActions, types.String),
			"deniedActions":      llx.ArrayData(deniedActions, types.String),
			"allowedDataActions": llx.ArrayData(allowedDataActions, types.String),
			"deniedDataActions":  llx.ArrayData(deniedDataActions, types.String),
		})
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (a *mqlAzureSubscriptionAuthorizationService) roleAssignments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := authorization.NewRoleAssignmentsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	// we're interested in subscription-level role definitions, so we scope this to the subscription,
	// on which this connection is running
	pager := client.NewListForSubscriptionPager(&authorization.RoleAssignmentsClientListForSubscriptionOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, roleAssignment := range page.Value {
			if roleAssignment == nil {
				continue
			}
			mqlRoleAssignment, err := newMqlRoleAssignment(a.MqlRuntime, roleAssignment)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRoleAssignment)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionAuthorizationServiceRoleAssignmentInternal struct {
	cacheRoleDefinitionId string
}

func newMqlRoleAssignment(runtime *plugin.Runtime, roleAssignment *authorization.RoleAssignment) (*mqlAzureSubscriptionAuthorizationServiceRoleAssignment, error) {
	// Properties is a nullable pointer; the args map dereferences it throughout,
	// so normalize to an empty struct to avoid a panic (mirrors the
	// denyAssignments/classicAdministrators paths below).
	if roleAssignment.Properties == nil {
		roleAssignment.Properties = &authorization.RoleAssignmentProperties{}
	}
	principalType := string(convert.ToValue(roleAssignment.Properties.PrincipalType))
	r, err := CreateResource(runtime, "azure.subscription.authorizationService.roleAssignment",
		map[string]*llx.RawData{
			"__id":          llx.StringDataPtr(roleAssignment.ID),
			"id":            llx.StringDataPtr(roleAssignment.Name), // name is the id :-)
			"description":   llx.StringDataPtr(roleAssignment.Properties.Description),
			"scope":         llx.StringDataPtr(roleAssignment.Properties.Scope),
			"principalId":   llx.StringDataPtr(roleAssignment.Properties.PrincipalID),
			"principalType": llx.StringData(principalType),
			"condition":     llx.StringDataPtr(roleAssignment.Properties.Condition),
			"createdAt":     llx.TimeDataPtr(roleAssignment.Properties.CreatedOn),
			"updatedAt":     llx.TimeDataPtr(roleAssignment.Properties.UpdatedOn),
		})
	if err != nil {
		return nil, err
	}

	mqlRoleDefinition := r.(*mqlAzureSubscriptionAuthorizationServiceRoleAssignment)
	if roleAssignment.Properties.RoleDefinitionID != nil {
		mqlRoleDefinition.cacheRoleDefinitionId = *roleAssignment.Properties.RoleDefinitionID
	}
	return mqlRoleDefinition, nil
}

// roleAssignmentsForScope lists the effective role assignments at an ARM scope.
// NewListForScopePager with no filter returns assignments made at the scope
// itself plus everything inherited from the resource group, subscription, and
// management-group ancestors, so the result is effective RBAC access to the
// resource rather than just what was assigned directly on it.
//
// Reading role assignments needs Microsoft.Authorization/roleAssignments/read,
// which a credential scoped only to the resource's own data plane may not hold.
// A 403 degrades to the assignments resolved so far rather than failing the
// whole query.
func roleAssignmentsForScope(runtime *plugin.Runtime, scope string, what string) ([]any, error) {
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	resourceID, err := ParseResourceID(scope)
	if err != nil {
		return nil, err
	}

	client, err := authorization.NewRoleAssignmentsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := client.NewListForScopePager(scope, &authorization.RoleAssignmentsClientListForScopeOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msgf("could not list %s role assignments due to access denied", what)
				return res, nil
			}
			return nil, err
		}
		for _, roleAssignment := range page.Value {
			if roleAssignment == nil {
				continue
			}
			mqlRoleAssignment, err := newMqlRoleAssignment(runtime, roleAssignment)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRoleAssignment)
		}
	}
	return res, nil
}

// roleDefinitionId reports the ARM resource ID of the granted role. It is kept
// separate from role(), which resolves the definition itself and reports null
// for a role defined outside the subscription's listing: the raw ID is always
// known from the assignment, so an audit can still see which role was granted.
func (a *mqlAzureSubscriptionAuthorizationServiceRoleAssignment) roleDefinitionId() (string, error) {
	return a.cacheRoleDefinitionId, nil
}

func extractSubscriptionID(roleDefinitionID string) (string, error) {
	parts := strings.Split(roleDefinitionID, "/")

	for i, part := range parts {
		if part == "subscriptions" && i+1 < len(parts) {
			return parts[i+1], nil
		}
	}

	return "", fmt.Errorf("subscription ID not found in role definition ID")
}

func (a *mqlAzureSubscriptionAuthorizationServiceRoleAssignment) role() (*mqlAzureSubscriptionAuthorizationServiceRoleDefinition, error) {
	if a.cacheRoleDefinitionId == "" {
		a.Role.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Resolve against the connected subscription's role definitions. The
	// listing at subscription scope already includes definitions inherited
	// from parent management groups, so it covers assignments whose
	// roleDefinitionId is management-group scoped -- those carry no
	// "subscriptions" segment and cannot be parsed for one.
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	r, err := CreateResource(a.MqlRuntime, ResourceAzureSubscription, map[string]*llx.RawData{
		"__id":           llx.StringData("/subscriptions/" + conn.SubId()),
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, err
	}
	iam := r.(*mqlAzureSubscription).GetIam()
	if iam.Error != nil {
		return nil, iam.Error
	}
	if iam.Data == nil {
		return nil, errors.New("cannot resolve the authorization service for the subscription")
	}
	rolesVal := iam.Data.GetRoles()
	if rolesVal.Error != nil {
		return nil, rolesVal.Error
	}
	roles := rolesVal.Data
	for i := range roles {
		role, ok := roles[i].(*mqlAzureSubscriptionAuthorizationServiceRoleDefinition)
		if !ok {
			continue
		}
		// ARM resource IDs are case-insensitive.
		if strings.EqualFold(role.__id, a.cacheRoleDefinitionId) {
			return role, nil
		}
	}

	// A role defined at a child scope this listing does not cover. Report the
	// grant as unresolved rather than failing the whole assignment listing --
	// role.name is in the resource's @defaults, so an error here would break
	// the default rendering of every role assignment in the subscription.
	a.Role.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAzureSubscriptionAuthorizationService) managedIdentities() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := armmsi.NewUserAssignedIdentitiesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	// list user assigned identities; each identity's roleAssignments accessor
	// resolves its granted roles on demand by filtering the subscription's
	// (cached) role-assignment list by principal ID.
	pager := client.NewListBySubscriptionPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, v := range page.Value {
			if v == nil {
				continue
			}
			mqlManagedIdentity, err := newMqlManagedIdentity(a.MqlRuntime, v)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlManagedIdentity)
		}
	}
	return res, nil
}

// initAzureSubscriptionManagedIdentity resolves a managed identity that is
// referenced only by its resource ID (e.g. from a typed cross-reference) by
// fetching it on demand. When the identity was already listed by
// managedIdentities(), the runtime cache short-circuits this and the init
// never runs.
func initAzureSubscriptionManagedIdentity(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}
	idRaw, ok := args["__id"]
	if !ok {
		return args, nil, nil
	}
	id, ok := idRaw.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return args, nil, nil
	}
	name, err := resourceID.Component("userAssignedIdentities")
	if err != nil {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.AzureConnection)
	// The subscription's list already holds this managed identity, and holds it for every
	// other reference to it too. Only pay for a Get when the list cannot
	// answer -- a reference into another subscription, or one since deleted.
	if mi := lookupInServiceList(runtime, ResourceAzureSubscriptionAuthorizationService,
		func(s *mqlAzureSubscriptionAuthorizationService) *plugin.TValue[[]any] {
			return s.GetManagedIdentities()
		},
		id); mi != nil {
		return args, mi, nil
	}

	client, err := armmsi.NewUserAssignedIdentitiesClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}

	identity, err := client.Get(context.Background(), resourceID.ResourceGroup, name, nil)
	if err != nil {
		// The identity may be inaccessible (deleted, cross-subscription, or
		// access denied); fall back to the bare reference rather than
		// failing the surrounding query.
		return args, nil, nil
	}

	mqlIdentity, err := newMqlManagedIdentity(runtime, &identity.Identity)
	if err != nil {
		return nil, nil, err
	}
	return args, mqlIdentity, nil
}

type mqlAzureSubscriptionManagedIdentityInternal struct {
	cacheResourceID string
	cacheSystemData any
}

func newMqlManagedIdentity(runtime *plugin.Runtime, managedIdentity *armmsi.Identity) (*mqlAzureSubscriptionManagedIdentity, error) {
	// Properties (and the *TenantID inside it) are nullable; guard before
	// dereferencing to avoid a panic on a partially-populated identity.
	var clientID, principalID, tenantID *string
	if p := managedIdentity.Properties; p != nil {
		clientID = p.ClientID
		principalID = p.PrincipalID
		tenantID = (*string)(p.TenantID)
	}
	r, err := CreateResource(runtime, "azure.subscription.managedIdentity",
		map[string]*llx.RawData{
			"__id":        llx.StringDataPtr(managedIdentity.ID),
			"name":        llx.StringDataPtr(managedIdentity.Name),
			"clientId":    llx.StringDataPtr(clientID),
			"principalId": llx.StringDataPtr(principalID),
			"tenantId":    llx.StringDataPtr(tenantID),
		})
	if err != nil {
		return nil, err
	}

	mqlManagedIdentity := r.(*mqlAzureSubscriptionManagedIdentity)
	mqlManagedIdentity.cacheResourceID = convert.ToValue(managedIdentity.ID)

	sysData, err := convert.JsonToDict(managedIdentity.SystemData)
	if err != nil {
		return nil, err
	}
	mqlManagedIdentity.cacheSystemData = sysData

	return mqlManagedIdentity, nil
}

func (a *mqlAzureSubscriptionManagedIdentity) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.__id, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionManagedIdentity) roleAssignments() ([]any, error) {
	return roleAssignmentsForPrincipal(a.MqlRuntime, a.PrincipalId.Data)
}

// roleAssignmentsForPrincipal returns the subscription role assignments granted
// directly to a principal, identified by its object/principal ID. It filters
// the subscription's role-assignment list (which the runtime caches), so every
// caller shares a single API fetch rather than issuing a per-principal query.
// An empty principalId yields no assignments.
//
// This is the identity-to-privilege edge of a resource's attack path: a managed
// identity (system- or user-assigned) resolves to the roles it holds, and each
// role assignment resolves further to its role definition and permissions.
func roleAssignmentsForPrincipal(runtime *plugin.Runtime, principalId string) ([]any, error) {
	if principalId == "" {
		return []any{}, nil
	}
	conn := runtime.Connection.(*connection.AzureConnection)
	// azure.subscription has no id() fallback here (only subscriptionId is
	// known), so pass __id explicitly; otherwise every synthesized subscription
	// shares the empty cache key.
	r, err := CreateResource(runtime, ResourceAzureSubscription, map[string]*llx.RawData{
		"__id":           llx.StringData("/subscriptions/" + conn.SubId()),
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, err
	}
	sub := r.(*mqlAzureSubscription)
	// Surface a failure to resolve IAM. Returning an empty list would report
	// "this identity holds no roles", which is the most dangerous possible
	// wrong answer for a privilege audit.
	iamVal := sub.GetIam()
	if iamVal.Error != nil {
		return nil, iamVal.Error
	}
	iam := iamVal.Data
	if iam == nil {
		return nil, errors.New("cannot resolve the authorization service for the subscription")
	}
	all := iam.GetRoleAssignments()
	if all.Error != nil {
		return nil, all.Error
	}
	return filterRoleAssignmentsByPrincipal(all.Data, principalId), nil
}

// filterRoleAssignmentsByPrincipal returns the role assignments whose principal
// ID matches the given principal.
func filterRoleAssignmentsByPrincipal(assignments []any, principalId string) []any {
	res := []any{}
	for _, ra := range assignments {
		assignment, ok := ra.(*mqlAzureSubscriptionAuthorizationServiceRoleAssignment)
		if !ok {
			continue
		}
		if assignment.PrincipalId.Data == principalId {
			res = append(res, assignment)
		}
	}
	return res
}

// listFederatedIdentityCredentials reads the federated identity credentials of
// a user-assigned identity. A system-assigned identity has no resource of its
// own to hang credentials on, so it reports none without a request.
func (a *mqlAzureSubscriptionManagedIdentity) listFederatedIdentityCredentials() ([]*armmsi.FederatedIdentityCredential, error) {
	if a.cacheResourceID == "" {
		return nil, nil
	}
	resourceID, err := ParseResourceID(a.cacheResourceID)
	if err != nil {
		return nil, err
	}
	name, err := resourceID.Component("userAssignedIdentities")
	if err != nil {
		return nil, err
	}

	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	client, err := armmsi.NewFederatedIdentityCredentialsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := client.NewListPager(resourceID.ResourceGroup, name, nil)
	res := []*armmsi.FederatedIdentityCredential{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, fic := range page.Value {
			if fic != nil {
				res = append(res, fic)
			}
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionManagedIdentity) federatedIdentityCredentials() ([]any, error) {
	fics, err := a.listFederatedIdentityCredentials()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, fic := range fics {
		entry := map[string]any{
			"name": convert.ToValue(fic.Name),
		}
		if p := fic.Properties; p != nil {
			entry["issuer"] = convert.ToValue(p.Issuer)
			entry["subject"] = convert.ToValue(p.Subject)
			entry["audiences"] = federatedCredentialAudiences(p.Audiences)
		}
		res = append(res, entry)
	}
	return res, nil
}

// federatedCredentialAudiences copies the audience list, skipping nil entries.
func federatedCredentialAudiences(audiences []*string) []any {
	res := []any{}
	for _, aud := range audiences {
		if aud != nil {
			res = append(res, *aud)
		}
	}
	return res
}

// federatedCredentialArgs maps a federated identity credential onto the fields
// of azure.subscription.managedIdentity.federatedCredential. An absent issuer
// or subject reads as null.
func federatedCredentialArgs(fic *armmsi.FederatedIdentityCredential) map[string]*llx.RawData {
	var issuer, subject *string
	audiences := []any{}
	if p := fic.Properties; p != nil {
		issuer = p.Issuer
		subject = p.Subject
		audiences = federatedCredentialAudiences(p.Audiences)
	}
	return map[string]*llx.RawData{
		"id":        llx.StringDataPtr(fic.ID),
		"name":      llx.StringDataPtr(fic.Name),
		"issuer":    llx.StringDataPtr(issuer),
		"subject":   llx.StringDataPtr(subject),
		"audiences": llx.ArrayData(audiences, types.String),
	}
}

func (a *mqlAzureSubscriptionManagedIdentity) federatedCredentials() ([]any, error) {
	fics, err := a.listFederatedIdentityCredentials()
	if err != nil {
		return nil, classifyAzureRefusal(err, "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/read")
	}
	res := []any{}
	for _, fic := range fics {
		mqlFic, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionManagedIdentityFederatedCredential, federatedCredentialArgs(fic))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFic)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionManagedIdentityFederatedCredential) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAuthorizationServiceDenyAssignment) id() (string, error) {
	return a.Id.Data, nil
}

// denyAssignments lists subscription-scoped read-only deny rules. Includes managed-app deny
// assignments and any custom deny rules. Required for "no Owner can delete X" verification.
func (a *mqlAzureSubscriptionAuthorizationService) denyAssignments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId := a.SubscriptionId.Data

	client, err := authorization.NewDenyAssignmentsClient(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, da := range page.Value {
			if da == nil {
				continue
			}
			var denyName, description, scope string
			var doNotApplyToChild, isSystemProtected *bool
			var perms, principals, excludePrincipals []any
			if p := da.Properties; p != nil {
				if p.DenyAssignmentName != nil {
					denyName = *p.DenyAssignmentName
				}
				if p.Description != nil {
					description = *p.Description
				}
				if p.Scope != nil {
					scope = *p.Scope
				}
				doNotApplyToChild = p.DoNotApplyToChildScopes
				isSystemProtected = p.IsSystemProtected
				for _, pm := range p.Permissions {
					if pm == nil {
						continue
					}
					if d, err := convert.JsonToDict(pm); err == nil {
						perms = append(perms, d)
					}
				}
				for _, pr := range p.Principals {
					if pr == nil {
						continue
					}
					if d, err := convert.JsonToDict(pr); err == nil {
						principals = append(principals, d)
					}
				}
				for _, pr := range p.ExcludePrincipals {
					if pr == nil {
						continue
					}
					if d, err := convert.JsonToDict(pr); err == nil {
						excludePrincipals = append(excludePrincipals, d)
					}
				}
			}

			mqlDa, err := CreateResource(a.MqlRuntime, "azure.subscription.authorizationService.denyAssignment",
				map[string]*llx.RawData{
					"id":                      llx.StringDataPtr(da.ID),
					"name":                    llx.StringDataPtr(da.Name),
					"type":                    llx.StringDataPtr(da.Type),
					"denyAssignmentName":      llx.StringData(denyName),
					"description":             llx.StringData(description),
					"doNotApplyToChildScopes": llx.BoolDataPtr(doNotApplyToChild),
					"isSystemProtected":       llx.BoolDataPtr(isSystemProtected),
					"scope":                   llx.StringData(scope),
					"permissions":             llx.ArrayData(perms, types.Dict),
					"principals":              llx.ArrayData(principals, types.Dict),
					"excludePrincipals":       llx.ArrayData(excludePrincipals, types.Dict),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDa)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionAuthorizationServiceClassicAdministrator) id() (string, error) {
	return a.Id.Data, nil
}

// azureProviderNotInRegion reports whether the error is ARM saying the resource
// provider is not deployed in that region.
//
// A subscription's location list includes staging and edge regions that most
// services never ship to, so any per-region fan-out hits this routinely. It
// means there is nothing there to find, which is a different thing from being
// unable to look.
func azureProviderNotInRegion(err error) bool {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	return respErr.ErrorCode == "NoRegisteredProviderFound"
}

// azureClassicAdministratorsRetired reports whether the error is ARM saying the
// classic administrators resource type no longer exists.
//
// The retirement removed the type from the Microsoft.Authorization namespace
// rather than emptying it, so ARM answers 404 InvalidResourceType. The code is
// checked alongside the status so that a genuinely missing subscription, which
// is also a 404 but carries SubscriptionNotFound, still reports as the error it
// is.
func azureClassicAdministratorsRetired(err error) bool {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	return respErr.StatusCode == http.StatusNotFound && respErr.ErrorCode == "InvalidResourceType"
}

// classicAdministrators lists legacy ASM co-admins and service admins on the
// subscription. Distinct from RBAC role assignments, which roleAssignments
// covers.
//
// Azure retired classic subscription administrators on 31 August 2024 and
// removed the resource type with them, so every subscription now answers this
// with 404 InvalidResourceType. That is not a fault to report: it means the
// subscription has no classic administrators, which is also the answer an audit
// of this field is looking for. Returning the 404 instead failed the field on
// every subscription in existence.
func (a *mqlAzureSubscriptionAuthorizationService) classicAdministrators() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId := a.SubscriptionId.Data

	client, err := authorization.NewClassicAdministratorsClient(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if azureClassicAdministratorsRetired(err) {
				return []any{}, nil
			}
			return nil, err
		}
		for _, ca := range page.Value {
			if ca == nil {
				continue
			}
			var emailAddress, role string
			if ca.Properties != nil {
				if ca.Properties.EmailAddress != nil {
					emailAddress = *ca.Properties.EmailAddress
				}
				if ca.Properties.Role != nil {
					role = *ca.Properties.Role
				}
			}

			mqlCa, err := CreateResource(a.MqlRuntime, "azure.subscription.authorizationService.classicAdministrator",
				map[string]*llx.RawData{
					"id":           llx.StringDataPtr(ca.ID),
					"name":         llx.StringDataPtr(ca.Name),
					"type":         llx.StringDataPtr(ca.Type),
					"emailAddress": llx.StringData(emailAddress),
					"role":         llx.StringData(role),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlCa)
		}
	}
	return res, nil
}
