// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"
	"sync"

	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/serviceprincipals"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/stringx"
)

const (
	// Microsoft Entra Tenant IDs for first party apps as defined in
	// https://learn.microsoft.com/en-us/troubleshoot/azure/entra/entra-id/governance/verify-first-party-apps-sign-in
	MicrosoftEntraTenantID = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
	MicrosoftTenantID      = "72f988bf-86f1-41af-91ab-2d7cd011db47"
)

// index for service principal app roles
var (
	idxAppRoleMutex    = &sync.RWMutex{}
	idxOauthScopeMutex = &sync.RWMutex{}
	idxAppNamesMutex   = &sync.RWMutex{}
)

type roleCache struct {
	id         string
	desc       string
	permission string
}

type oauth2PermissionScope struct {
	id         string
	desc       string
	permission string
}

type PermissionIndexer interface {
	IndexAppName(spId, appName string)
	IndexAppRole(spId string, roles ...models.AppRoleable)
	IndexOauthScope(spId string, scopes ...models.PermissionScopeable)
}

// creates a new permission indexer to cache the service principal app roles and oauth scopes
type permissionIndexer struct {
	// permission index key : appId/roleID value: permission
	idxAppRoles map[string]*roleCache
	// app roles published by a service principal, keyed by service principal ID
	idxAppRolesBySp map[string][]*roleCache
	// permission index key : appId/permission value: permission
	idxOauthPermissionScopes map[string]*oauth2PermissionScope
	// index of app names by appId
	idxAppNames map[string]string
}

func (idx *permissionIndexer) initAppRoleIndex() {
	if idx.idxAppRoles == nil {
		idx.idxAppRoles = make(map[string]*roleCache)
	}
	if idx.idxAppRolesBySp == nil {
		idx.idxAppRolesBySp = make(map[string][]*roleCache)
	}
}

func (idx *permissionIndexer) initOauthPermissionScopeIndex() {
	if idx.idxOauthPermissionScopes == nil {
		idx.idxOauthPermissionScopes = make(map[string]*oauth2PermissionScope)
	}
}

func (idx *permissionIndexer) initAppNameIndex() {
	if idx.idxAppNames == nil {
		idx.idxAppNames = make(map[string]string)
	}
}

func (idx *permissionIndexer) IndexAppName(spId, name string) {
	idx.initAppNameIndex()
	idxAppNamesMutex.Lock()
	idx.idxAppNames[spId] = name
	idxAppNamesMutex.Unlock()
}

func (idx *permissionIndexer) appName(appId string) (string, bool) {
	if idx.idxAppNames == nil {
		return "", false
	}
	idxAppNamesMutex.RLock()
	name, ok := idx.idxAppNames[appId]
	idxAppNamesMutex.RUnlock()
	return name, ok
}

// index all app roles we've seen for service-accounts
func (idx *permissionIndexer) IndexAppRole(spId string, roles ...models.AppRoleable) {
	idx.initAppRoleIndex()
	idxAppRoleMutex.Lock()
	for _, r := range roles {
		roleId := r.GetId()
		if roleId == nil || roleId.String() == "" {
			continue
		}

		rCache := &roleCache{
			id:         roleId.String(),
			desc:       convert.ToValue(r.GetDisplayName()),
			permission: convert.ToValue(r.GetValue()),
		}

		idx.idxAppRoles[spId+"/"+rCache.id] = rCache
		idx.idxAppRoles[spId+"/"+rCache.permission] = rCache
		idx.idxAppRolesBySp[spId] = append(idx.idxAppRolesBySp[spId], rCache)
	}
	idxAppRoleMutex.Unlock()
}

// appRolesForSp returns all app roles published by a service principal
func (idx *permissionIndexer) appRolesForSp(spId string) []*roleCache {
	if idx.idxAppRolesBySp == nil {
		return nil
	}
	idxAppRoleMutex.RLock()
	roles := idx.idxAppRolesBySp[spId]
	idxAppRoleMutex.RUnlock()
	return roles
}

// appRole returns a role by appId and roleID
func (idx *permissionIndexer) appRole(spId, roleId string) (*roleCache, bool) {
	if idx.idxAppRoles == nil {
		return nil, false
	}
	idxAppRoleMutex.RLock()
	role, ok := idx.idxAppRoles[spId+"/"+roleId]
	idxAppRoleMutex.RUnlock()
	return role, ok
}

// index all oauth scopes we've seen for service-accounts
func (idx *permissionIndexer) IndexOauthScope(spId string, scopes ...models.PermissionScopeable) {
	idxOauthScopeMutex.Lock()
	idx.initOauthPermissionScopeIndex()
	for _, s := range scopes {
		scopeId := s.GetId()
		if scopeId == nil || scopeId.String() == "" {
			continue
		}

		scope := &oauth2PermissionScope{
			id:         scopeId.String(),
			desc:       convert.ToValue(s.GetAdminConsentDisplayName()),
			permission: convert.ToValue(s.GetValue()),
		}

		idx.idxOauthPermissionScopes[spId+"/"+scope.permission] = scope
	}
	idxOauthScopeMutex.Unlock()
}

func (idx *permissionIndexer) getOauthPermissionScope(appId, permission string) (*oauth2PermissionScope, bool) {
	if idx.idxOauthPermissionScopes == nil {
		return nil, false
	}
	idxOauthScopeMutex.RLock()
	scope, ok := idx.idxOauthPermissionScopes[appId+"/"+permission]
	idxOauthScopeMutex.RUnlock()
	return scope, ok
}

var servicePrincipalFields = []string{
	"id",
	"servicePrincipalType",
	"displayName",
	"appId",
	"appOwnerOrganizationId",
	"description",
	"tags",
	"accountEnabled",
	"homepage",
	"replyUrls",
	"appRoleAssignmentRequired",
	"notes",
	"applicationTemplateId",
	"loginUrl",
	"logoutUrl",
	"servicePrincipalNames",
	"signInAudience",
	// sources termsOfServiceUrl; omitting it leaves that field unset, not null
	"info",
	"preferredSingleSignOnMode",
	"notificationEmailAddresses",
	"verifiedPublisher",
	"appRoles",
	"oauth2PermissionScopes",
	"alternativeNames",
	"appDescription",
	"disabledByMicrosoftStatus",
	"keyCredentials",
	"passwordCredentials",
}

type mqlMicrosoftServiceprincipalInternal struct {
	// ids of the list this service principal was first created from; a
	// per-principal batched field fetches them together
	batchPeerIDs []string
}

func (m *mqlMicrosoftServiceprincipal) id() (string, error) {
	return m.Id.Data, nil
}

func (m *mqlMicrosoftServiceprincipalAssignment) id() (string, error) {
	return m.Id.Data, nil
}

func initMicrosoftServiceprincipal(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// we only look up the service principal if we have been supplied by its name and nothing else
	rawName, okName := args["name"]
	rawId, okId := args["id"]
	rawAppId, okAppId := args["appId"]

	if len(args) != 1 || (!okName && !okId && !okAppId) {
		return args, nil, nil
	}

	var filter func(sp *mqlMicrosoftServiceprincipal) bool

	if okId {
		id := rawId.Value.(string)
		filter = func(sp *mqlMicrosoftServiceprincipal) bool {
			return sp.Id.Data == id
		}
	} else if okAppId {
		appId := rawAppId.Value.(string)
		filter = func(sp *mqlMicrosoftServiceprincipal) bool {
			return sp.AppId.Data == appId
		}
	} else if okName {
		// NOTE: be aware that service principal names are not unique
		name := rawName.Value.(string)
		filter = func(sp *mqlMicrosoftServiceprincipal) bool {
			return sp.Name.Data == name
		}
	}

	if filter == nil {
		return nil, nil, errors.New("invalid filter")
	}

	mqlResource, err := runtime.CreateResource(runtime, "microsoft", nil)
	if err != nil {
		return nil, nil, err
	}
	microsoftResource := mqlResource.(*mqlMicrosoft)
	servicePrincipalList := microsoftResource.GetServiceprincipals()
	if servicePrincipalList.Error != nil {
		return nil, nil, servicePrincipalList.Error
	}
	for i := range servicePrincipalList.Data {
		sp := servicePrincipalList.Data[i].(*mqlMicrosoftServiceprincipal)
		if filter(sp) {
			return nil, sp, nil
		}
	}

	return nil, nil, errServicePrincipalNotFound
}

// errServicePrincipalNotFound is what initMicrosoftServiceprincipal returns
// when the tenant's full service principal list holds no match, which is how
// a reference to a deleted service principal surfaces.
var errServicePrincipalNotFound = errors.New("service principal not found")

// enterprise applications are just service principals with a special tag, attached to them
// this is the same way the portal UI fetches the enterprise apps by looking for the tag
func (a *mqlMicrosoft) enterpriseApplications() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	top := int32(999)
	filter := "tags/Any(x: x eq 'WindowsAzureActiveDirectoryIntegratedApp')"
	params := &serviceprincipals.ServicePrincipalsRequestBuilderGetQueryParameters{
		Top:    &top,
		Filter: &filter,
	}
	return fetchServicePrincipals(a.MqlRuntime, conn, params, nil)
}

func (a *mqlMicrosoft) serviceprincipals() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	top := int32(999)
	params := &serviceprincipals.ServicePrincipalsRequestBuilderGetQueryParameters{
		Top:    &top,
		Select: servicePrincipalFields,
	}

	return fetchServicePrincipals(a.MqlRuntime, conn, params, a)
}

func fetchServicePrincipals(runtime *plugin.Runtime, conn *connection.Ms365Connection, params *serviceprincipals.ServicePrincipalsRequestBuilderGetQueryParameters, permissionIndexer PermissionIndexer) ([]any, error) {
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	resp, err := graphClient.ServicePrincipals().Get(ctx, &serviceprincipals.ServicePrincipalsRequestBuilderGetRequestConfiguration{
		QueryParameters: params,
	})
	if err != nil {
		return nil, transformError(err)
	}
	sps, err := iterate[*models.ServicePrincipal](ctx, resp, graphClient.GetAdapter(), serviceprincipals.CreateDeltaGetResponseFromDiscriminatorValue)
	if err != nil {
		return nil, transformError(err)
	}
	// the ids of this list are the batch peers for per-principal fields such
	// as assignments, so enterprise applications batch among themselves
	// instead of pulling in every service principal in the tenant
	peerIDs := make([]string, 0, len(sps))
	for _, sp := range sps {
		if id := sp.GetId(); id != nil {
			peerIDs = append(peerIDs, *id)
		}
	}

	res := []any{}
	for _, sp := range sps {
		// create resource
		mqlResource, err := newMqlMicrosoftServicePrincipal(runtime, sp)
		if err != nil {
			return nil, err
		}
		if mqlResource.batchPeerIDs == nil {
			mqlResource.batchPeerIDs = peerIDs
		}

		// also fill up the index
		if permissionIndexer != nil {
			permissionIndexer.IndexAppName(convert.ToValue(sp.GetId()), convert.ToValue(sp.GetDisplayName()))
			permissionIndexer.IndexAppRole(convert.ToValue(sp.GetId()), sp.GetAppRoles()...)
			permissionIndexer.IndexOauthScope(convert.ToValue(sp.GetId()), sp.GetOauth2PermissionScopes()...)
		}
		res = append(res, mqlResource)
	}

	return res, nil
}

func newMqlMicrosoftServicePrincipal(runtime *plugin.Runtime, sp models.ServicePrincipalable) (*mqlMicrosoftServiceprincipal, error) {
	hideApp := stringx.Contains(sp.GetTags(), "HideApp")

	var appVerifiedOrganizationID string
	if sp.GetAppOwnerOrganizationId() != nil {
		appVerifiedOrganizationID = sp.GetAppOwnerOrganizationId().String()
	}

	verifiedPublisher, _ := convert.JsonToDict(newVerifiedPublisher(sp.GetVerifiedPublisher()))

	oauth2PermissionScopes, err := convert.JsonToDictSlice(newPermissionScopableList(sp.GetOauth2PermissionScopes()))
	if err != nil {
		return nil, err
	}

	certificates := []any{}
	for _, keyCredential := range sp.GetKeyCredentials() {
		cert, err := newMqlMicrosoftKeyCredential(runtime, keyCredential)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, cert)
	}

	secrets := []any{}
	for _, passwordCredential := range sp.GetPasswordCredentials() {
		secret, err := newMqlMicrosoftPasswordCredential(runtime, passwordCredential)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, secret)
	}

	mqlAppRoleList := []any{}
	appRoles := sp.GetAppRoles()
	for i := range appRoles {
		appRole := appRoles[i]

		uuid := appRole.GetId()
		if uuid == nil {
			log.Debug().Msg("appRole ID is nil")
			continue
		}

		mqlAppRoleResource, err := CreateResource(runtime, "microsoft.application.role",
			map[string]*llx.RawData{
				"__id":               llx.StringData(uuid.String()),
				"id":                 llx.StringData(uuid.String()),
				"name":               llx.StringDataPtr(appRole.GetDisplayName()),
				"description":        llx.StringDataPtr(appRole.GetDescription()),
				"value":              llx.StringDataPtr(appRole.GetValue()),
				"allowedMemberTypes": llx.ArrayData(convert.SliceAnyToInterface(appRole.GetAllowedMemberTypes()), types.String),
				"isEnabled":          llx.BoolDataPtr(appRole.GetIsEnabled()),
			})
		if err != nil {
			return nil, err
		}
		mqlAppRoleList = append(mqlAppRoleList, mqlAppRoleResource)
	}

	args := map[string]*llx.RawData{
		"id":                         llx.StringDataPtr(sp.GetId()),
		"type":                       llx.StringDataPtr(sp.GetServicePrincipalType()),
		"name":                       llx.StringDataPtr(sp.GetDisplayName()),
		"appId":                      llx.StringDataPtr(sp.GetAppId()),
		"appOwnerOrganizationId":     llx.StringData(appVerifiedOrganizationID),
		"description":                llx.StringDataPtr(sp.GetDescription()),
		"tags":                       llx.ArrayData(convert.SliceAnyToInterface(sp.GetTags()), types.String),
		"enabled":                    llx.BoolDataPtr(sp.GetAccountEnabled()),
		"homepageUrl":                llx.StringDataPtr(sp.GetHomepage()),
		"replyUrls":                  llx.ArrayData(convert.SliceAnyToInterface(sp.GetReplyUrls()), types.String),
		"assignmentRequired":         llx.BoolDataPtr(sp.GetAppRoleAssignmentRequired()),
		"visibleToUsers":             llx.BoolData(!hideApp),
		"notes":                      llx.StringDataPtr(sp.GetNotes()),
		"applicationTemplateId":      llx.StringDataPtr(sp.GetApplicationTemplateId()),
		"loginUrl":                   llx.StringDataPtr(sp.GetLoginUrl()),
		"logoutUrl":                  llx.StringDataPtr(sp.GetLogoutUrl()),
		"servicePrincipalNames":      llx.ArrayData(convert.SliceAnyToInterface(sp.GetServicePrincipalNames()), types.String),
		"signInAudience":             llx.StringDataPtr(sp.GetSignInAudience()),
		"preferredSingleSignOnMode":  llx.StringDataPtr(sp.GetPreferredSingleSignOnMode()),
		"notificationEmailAddresses": llx.ArrayData(convert.SliceAnyToInterface(sp.GetNotificationEmailAddresses()), types.String),
		"appRoleAssignmentRequired":  llx.BoolDataPtr(sp.GetAppRoleAssignmentRequired()),
		"verifiedPublisher":          llx.DictData(verifiedPublisher),
		"appRoles":                   llx.ArrayData(mqlAppRoleList, types.Resource("microsoft.application.role")),
		"alternativeNames":           llx.ArrayData(convert.SliceAnyToInterface(sp.GetAlternativeNames()), types.String),
		"appDescription":             llx.StringDataPtr(sp.GetAppDescription()),
		"disabledByMicrosoftStatus":  llx.StringDataPtr(sp.GetDisabledByMicrosoftStatus()),
		"keyCredentials":             llx.ArrayData(certificates, types.Resource("microsoft.keyCredential")),
		"passwordCredentials":        llx.ArrayData(secrets, types.Resource("microsoft.passwordCredential")),
		"oauth2PermissionScopes":     llx.ArrayData(oauth2PermissionScopes, types.Dict),
	}
	// Set unconditionally. A CreateResource arg map must never omit a declared
	// field: an omitted key leaves the field UNSET rather than null, and an
	// unset field crosses the plugin boundary as an empty DataRes that surfaces
	// client-side as "encountered a primitive with no type information", with
	// no attribution back to the field.
	var termsOfServiceUrl *string
	if info := sp.GetInfo(); info != nil {
		termsOfServiceUrl = info.GetTermsOfServiceUrl()
	}
	args["termsOfServiceUrl"] = llx.StringDataPtr(termsOfServiceUrl)

	mqlResource, err := CreateResource(runtime, "microsoft.serviceprincipal", args)
	if err != nil {
		return nil, err
	}
	return mqlResource.(*mqlMicrosoftServiceprincipal), nil
}

func (a *mqlMicrosoftServiceprincipal) isFirstParty() (bool, error) {
	ownerId := a.AppOwnerOrganizationId.Data
	// e.g. O365 LinkedIn Connection and YammerOnOls do not have an owner
	if ownerId == MicrosoftEntraTenantID || ownerId == MicrosoftTenantID || ownerId == "" {
		return true, nil
	}
	return false, nil
}

// assignments returns the users, groups, and service principals assigned to
// this service principal. It is read from /servicePrincipals/{id}/appRoleAssignedTo
// rather than from an $expand on the list call: $expand on a directory-object
// relation is capped at 20 entries with no nextLink, and only one of the
// lists that create this resource asked for it, so whichever list ran first
// decided whether the cached resource had any assignments at all.
func (a *mqlMicrosoftServiceprincipal) assignments() ([]any, error) {
	ms, err := a.microsoftParent()
	if err != nil {
		return nil, err
	}
	v, err := ms.spBatches.assignments.resolve(a.Id.Data, a.batchPeerIDs, ms.loadServicePrincipalAssignments)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return []any{}, nil
	}
	return v.([]any), nil
}

// loadServicePrincipalAssignments fetches appRoleAssignedTo for the given
// service principals in one batched Graph request, draining any nextLink of
// each sub-response, and builds the microsoft.serviceprincipal.assignment
// lists.
func (m *mqlMicrosoft) loadServicePrincipalAssignments(ids []string) (map[string]any, map[string]error, error) {
	conn := m.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, nil, err
	}
	assigned, errs, err := fetchAppRoleAssignedTo(context.Background(), graphClient, ids)
	if err != nil {
		return nil, nil, err
	}
	data := make(map[string]any, len(assigned))
	for id, list := range assigned {
		res, err := newMqlServicePrincipalAssignments(m.MqlRuntime, list)
		if err != nil {
			errs[id] = err
			continue
		}
		data[id] = res
	}
	return data, errs, nil
}

// fetchAppRoleAssignedTo returns the fully paged appRoleAssignedTo collection
// of each service principal, keyed by service principal id. A per-principal
// failure lands in the error map without failing the others.
func fetchAppRoleAssignedTo(ctx context.Context, graphClient *msgraphsdkgo.GraphServiceClient, ids []string) (map[string][]models.AppRoleAssignmentable, map[string]error, error) {
	top := int32(999)
	reqs := make([]batchItemRequest, 0, len(ids))
	for _, id := range ids {
		info, err := graphClient.ServicePrincipals().ByServicePrincipalId(id).AppRoleAssignedTo().ToGetRequestInformation(ctx,
			&serviceprincipals.ItemAppRoleAssignedToRequestBuilderGetRequestConfiguration{
				QueryParameters: &serviceprincipals.ItemAppRoleAssignedToRequestBuilderGetQueryParameters{Top: &top},
			})
		if err != nil {
			return nil, nil, transformError(err)
		}
		reqs = append(reqs, batchItemRequest{key: id, reqInfo: info})
	}

	batch, err := batchGet[*models.AppRoleAssignmentCollectionResponse](ctx, graphClient.GetAdapter(), reqs, models.CreateAppRoleAssignmentCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, nil, err
	}

	adapter := graphClient.GetAdapter()
	data := make(map[string][]models.AppRoleAssignmentable, len(ids))
	errs := make(map[string]error)
	for _, id := range ids {
		if e := batch.errs[id]; e != nil {
			errs[id] = e
			continue
		}
		var assigned []models.AppRoleAssignmentable
		if coll := batch.results[id]; coll != nil {
			// a $batch sub-response carries only the first page
			assigned, err = iterate[models.AppRoleAssignmentable](ctx, coll, adapter, models.CreateAppRoleAssignmentCollectionResponseFromDiscriminatorValue)
			if err != nil {
				errs[id] = err
				continue
			}
		}
		data[id] = assigned
	}
	return data, errs, nil
}

func newMqlServicePrincipalAssignments(runtime *plugin.Runtime, assigned []models.AppRoleAssignmentable) ([]any, error) {
	res := []any{}
	for _, a := range assigned {
		if a == nil || a.GetId() == nil {
			continue
		}
		assignment, err := CreateResource(runtime, "microsoft.serviceprincipal.assignment", map[string]*llx.RawData{
			"id":          llx.StringDataPtr(a.GetId()),
			"displayName": llx.StringDataPtr(a.GetPrincipalDisplayName()),
			"type":        llx.StringDataPtr(a.GetPrincipalType()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, assignment)
	}
	return res, nil
}

func (a *mqlMicrosoftServiceprincipal) permissions() ([]any, error) {
	ms, err := a.microsoftParent()
	if err != nil {
		return nil, err
	}
	// service principals are not kept in a dedicated index; the full set comes
	// from the serviceprincipals list, which is the batch's id universe
	spList := ms.GetServiceprincipals()
	if spList.Error != nil {
		return nil, spList.Error
	}
	ids := make([]string, 0, len(spList.Data))
	for _, item := range spList.Data {
		ids = append(ids, item.(*mqlMicrosoftServiceprincipal).Id.Data)
	}
	v, err := ms.spBatches.permissions.resolve(a.Id.Data, ids, ms.loadServicePrincipalPermissions)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return []any{}, nil
	}
	return v.([]any), nil
}

// microsoftParent returns the singleton microsoft resource, which owns the
// app-role index and the per-service-principal batched-field caches.
func (a *mqlMicrosoftServiceprincipal) microsoftParent() (*mqlMicrosoft, error) {
	resource, err := CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoft), nil
}

// loadServicePrincipalPermissions fetches the application (appRoleAssignments)
// and delegated (oauth2PermissionGrants) permissions of the given service
// principals in two batched Graph requests, then assembles the per-principal
// microsoft.application.permission lists.
func (m *mqlMicrosoft) loadServicePrincipalPermissions(ids []string) (map[string]any, map[string]error, error) {
	conn := m.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, nil, err
	}

	// resolving the service principals builds up the app-role index that the
	// permission assembly relies on. GetServiceprincipals does not resolve the
	// permissions field, so it cannot re-enter the cache mutex held here.
	spList := m.GetServiceprincipals()
	if spList.Error != nil {
		return nil, nil, spList.Error
	}

	ctx := context.Background()
	roleReqs := make([]batchItemRequest, 0, len(ids))
	oauthReqs := make([]batchItemRequest, 0, len(ids))
	for _, id := range ids {
		roleInfo, err := graphClient.ServicePrincipals().ByServicePrincipalId(id).AppRoleAssignments().ToGetRequestInformation(ctx, nil)
		if err != nil {
			return nil, nil, transformError(err)
		}
		roleReqs = append(roleReqs, batchItemRequest{key: id, reqInfo: roleInfo})

		oauthInfo, err := graphClient.ServicePrincipals().ByServicePrincipalId(id).Oauth2PermissionGrants().ToGetRequestInformation(ctx, nil)
		if err != nil {
			return nil, nil, transformError(err)
		}
		oauthReqs = append(oauthReqs, batchItemRequest{key: id, reqInfo: oauthInfo})
	}

	roleRes, err := batchGet[*models.AppRoleAssignmentCollectionResponse](ctx, graphClient.GetAdapter(), roleReqs, models.CreateAppRoleAssignmentCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, nil, err
	}
	oauthRes, err := batchGet[*models.OAuth2PermissionGrantCollectionResponse](ctx, graphClient.GetAdapter(), oauthReqs, models.CreateOAuth2PermissionGrantCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, nil, err
	}

	adapter := graphClient.GetAdapter()
	data := make(map[string]any, len(ids))
	errs := make(map[string]error)
	for _, id := range ids {
		if e := roleRes.errs[id]; e != nil {
			errs[id] = e
			continue
		}
		if e := oauthRes.errs[id]; e != nil {
			errs[id] = e
			continue
		}

		// A $batch sub-response carries only the first page of a collection.
		// Drain any @odata.nextLink so service principals with many role
		// assignments or grants are not silently truncated; the PageIterator
		// makes no additional HTTP calls when the first page is already
		// complete, which is the common case.
		var roleAssignments []models.AppRoleAssignmentable
		if coll := roleRes.results[id]; coll != nil {
			roleAssignments, err = iterate[models.AppRoleAssignmentable](ctx, coll, adapter, models.CreateAppRoleAssignmentCollectionResponseFromDiscriminatorValue)
			if err != nil {
				errs[id] = err
				continue
			}
		}
		var oauthGrants []models.OAuth2PermissionGrantable
		if coll := oauthRes.results[id]; coll != nil {
			oauthGrants, err = iterate[models.OAuth2PermissionGrantable](ctx, coll, adapter, models.CreateOAuth2PermissionGrantCollectionResponseFromDiscriminatorValue)
			if err != nil {
				errs[id] = err
				continue
			}
		}

		list, err := m.buildServicePrincipalPermissions(roleAssignments, oauthGrants)
		if err != nil {
			errs[id] = err
			continue
		}
		data[id] = list
	}
	return data, errs, nil
}

// buildServicePrincipalPermissions assembles the granted and available
// application and delegated permissions for a single service principal from
// its fully-paged appRoleAssignments and oauth2PermissionGrants.
func (m *mqlMicrosoft) buildServicePrincipalPermissions(
	appRolesAssignments []models.AppRoleAssignmentable,
	delegatedRolesAssignments []models.OAuth2PermissionGrantable,
) ([]any, error) {
	list := []any{}
	// track which app roles are granted, keyed by resourceSpId/roleId, and the
	// display name of each resource service principal the application touches
	grantedRoleKeys := map[string]bool{}
	resourceSpNames := map[string]string{}
	for _, roleAssignment := range appRolesAssignments {
		assignmentID := roleAssignment.GetId()
		spId := roleAssignment.GetResourceId()  // id of the service account
		roleId := roleAssignment.GetAppRoleId() // id of the app role on the service account

		if assignmentID == nil || spId == nil || roleId == nil {
			continue
		}
		grantedRoleKeys[spId.String()+"/"+roleId.String()] = true
		resourceSpNames[spId.String()] = convert.ToValue(roleAssignment.GetResourceDisplayName())
		role, ok := m.appRole(spId.String(), roleId.String())
		if !ok {
			log.Debug().Msgf("role not found in cache: %v", roleId)
			continue
		}

		assignment, err := CreateResource(m.MqlRuntime, "microsoft.application.permission", map[string]*llx.RawData{
			"__id":        llx.StringDataPtr(assignmentID),
			"appId":       llx.StringData(spId.String()),
			"appName":     llx.StringDataPtr(roleAssignment.GetResourceDisplayName()),
			"description": llx.StringData(role.desc),
			"id":          llx.StringData(roleId.String()),
			"name":        llx.StringData(role.permission),
			"type":        llx.StringData("application"),
			"status":      llx.StringData("granted"),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, assignment)
	}

	// surface the app roles published by each resource the application already
	// has a grant on but has not been assigned, so audits can see the unused
	// capability the application could request
	for resourceSpId, resourceName := range resourceSpNames {
		for _, role := range m.appRolesForSp(resourceSpId) {
			key := resourceSpId + "/" + role.id
			if grantedRoleKeys[key] {
				continue
			}
			grantedRoleKeys[key] = true // also dedupes repeated roles

			assignment, err := CreateResource(m.MqlRuntime, "microsoft.application.permission", map[string]*llx.RawData{
				"__id":        llx.StringData(key + "/available"),
				"appId":       llx.StringData(resourceSpId),
				"appName":     llx.StringData(resourceName),
				"description": llx.StringData(role.desc),
				"id":          llx.StringData(role.id),
				"name":        llx.StringData(role.permission),
				"type":        llx.StringData("application"),
				"status":      llx.StringData("available"),
			})
			if err != nil {
				return nil, err
			}
			list = append(list, assignment)
		}
	}

	for _, roleAssignment := range delegatedRolesAssignments {

		spId := roleAssignment.GetResourceId() // id of the service account
		if spId == nil {
			continue
		}

		appName, _ := m.appName(*spId)
		scope := roleAssignment.GetScope()
		if scope == nil {
			continue
		}

		// one line can include multiple scopes
		scopeList := strings.Split(*scope, " ")

		for _, scopeEntry := range scopeList {
			if scopeEntry == "" {
				continue
			}
			id := convert.ToValue(roleAssignment.GetId())
			desc := ""
			role, ok := m.getOauthPermissionScope(*spId, scopeEntry)
			if ok {
				desc = role.desc
			}

			assignment, err := CreateResource(m.MqlRuntime, "microsoft.application.permission", map[string]*llx.RawData{
				"__id":        llx.StringData(id + "/" + scopeEntry),
				"appId":       llx.StringDataPtr(spId),
				"appName":     llx.StringData(appName),
				"description": llx.StringData(desc),
				"id":          llx.StringData(id),
				"name":        llx.StringData(scopeEntry),
				"type":        llx.StringData("delegated"),
				"status":      llx.StringData("granted"),
			})
			if err != nil {
				return nil, err
			}
			list = append(list, assignment)
		}
	}
	return list, nil
}

// owners returns the users who own the service principal. Owners that are
// service principals are skipped for the same reason as on an application.
// https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-owners?view=graph-rest-1.0
func (a *mqlMicrosoftServiceprincipal) owners() ([]any, error) {
	ms, err := a.microsoftParent()
	if err != nil {
		return nil, err
	}
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	// the same user fields initMicrosoftUser selects, so reading an owner's
	// details does not cost a Graph call per owner
	resp, err := graphClient.ServicePrincipals().ByServicePrincipalId(a.Id.Data).Owners().Get(ctx, &serviceprincipals.ItemOwnersRequestBuilderGetRequestConfiguration{
		QueryParameters: &serviceprincipals.ItemOwnersRequestBuilderGetQueryParameters{
			Select: userSelectFields,
		},
	})
	if err != nil {
		return nil, classifyGraphError(err, "Application.Read.All")
	}
	owners, err := iterate[models.DirectoryObjectable](ctx, resp, graphClient.GetAdapter(), models.CreateDirectoryObjectCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, "Application.Read.All")
	}
	return newMqlOwnerUsers(ms, userOwners(owners))
}

// https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential?view=graph-rest-1.0
func (a *mqlMicrosoftServiceprincipal) federatedIdentityCredentials() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.ServicePrincipals().ByServicePrincipalId(a.Id.Data).FederatedIdentityCredentials().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, "Application.Read.All")
	}
	creds, err := iterate[models.FederatedIdentityCredentialable](ctx, resp, graphClient.GetAdapter(), models.CreateFederatedIdentityCredentialCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, "Application.Read.All")
	}
	return newMqlFederatedIdentityCredentials(a.MqlRuntime, a.Id.Data, creds)
}

// https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-appmanagementpolicies?view=graph-rest-1.0
func (a *mqlMicrosoftServiceprincipal) appManagementPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.ServicePrincipals().ByServicePrincipalId(a.Id.Data).AppManagementPolicies().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, "Application.Read.All", "Policy.Read.All")
	}
	policies, err := iterate[models.AppManagementPolicyable](ctx, resp, graphClient.GetAdapter(), models.CreateAppManagementPolicyCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, "Application.Read.All", "Policy.Read.All")
	}
	return newMqlAppManagementPolicies(a.MqlRuntime, policies)
}
