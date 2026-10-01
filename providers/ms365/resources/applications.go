// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	abstractions "github.com/microsoft/kiota-abstractions-go"
	"github.com/rs/zerolog/log"

	"github.com/microsoftgraph/msgraph-sdk-go/applications"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlMicrosoft) applications() (*mqlMicrosoftApplications, error) {
	mqlResource, err := CreateResource(a.MqlRuntime, "microsoft.applications", map[string]*llx.RawData{})
	return mqlResource.(*mqlMicrosoftApplications), err
}

func (a *mqlMicrosoftApplications) list() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	top := int32(500)
	opts := &applications.ApplicationsRequestBuilderGetRequestConfiguration{
		QueryParameters: &applications.ApplicationsRequestBuilderGetQueryParameters{
			Top: &top,
		},
	}
	resp, err := graphClient.Applications().Get(ctx, opts)
	if err != nil {
		return nil, transformError(err)
	}

	allApps, err := iterate[*models.Application](ctx, resp, graphClient.GetAdapter(), applications.CreateDeltaGetResponseFromDiscriminatorValue)
	if err != nil {
		return nil, transformError(err)
	}

	res := []any{}
	for _, app := range allApps {
		mqlResource, err := newMqlMicrosoftApplication(a.MqlRuntime, app)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlResource)
	}

	return res, nil
}

func (a *mqlMicrosoftApplications) count() (int64, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return 0, err
	}

	opts := &applications.CountRequestBuilderGetRequestConfiguration{Headers: abstractions.NewRequestHeaders()}
	opts.Headers.Add("ConsistencyLevel", "eventual")
	count, err := graphClient.Applications().Count().Get(context.Background(), opts)
	if err != nil {
		return 0, err
	}
	if count == nil {
		// This should never happen, but we better check
		return 0, errors.New("unable to count applications, counter parameter API returned nil")
	}

	return int64(*count), nil
}

// newMqlMicrosoftApplication creates a new mqlMicrosoftApplication resource
// see https://learn.microsoft.com/en-us/entra/identity-platform/reference-microsoft-graph-app-manifest for a
// better description of the fields
func newMqlMicrosoftApplication(runtime *plugin.Runtime, app models.Applicationable) (*mqlMicrosoftApplication, error) {
	// certificates
	var certificates []any
	keycredentials := app.GetKeyCredentials()
	for _, keycredential := range keycredentials {
		cert, err := newMqlMicrosoftKeyCredential(runtime, keycredential)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, cert)
	}
	// secrets
	var secrets []any
	clientSecrets := app.GetPasswordCredentials()
	for _, clientSecret := range clientSecrets {
		secret, err := newMqlMicrosoftPasswordCredential(runtime, clientSecret)
		if err != nil {
			return nil, err
		}
		secrets = append(secrets, secret)
	}

	// Each conversion is checked individually — the previous code threaded a
	// single err variable through all of them and only inspected the last one,
	// silently dropping any earlier failures.
	info, err := convert.JsonToDict(newAppInformationUrl(app.GetInfo()))
	if err != nil {
		return nil, err
	}
	// https://learn.microsoft.com/en-us/entra/identity-platform/reference-microsoft-graph-app-manifest#api-attribute
	apiInfo, err := convert.JsonToDict(newApiApplication(app.GetApi()))
	if err != nil {
		return nil, err
	}
	// https://learn.microsoft.com/en-us/entra/identity-platform/reference-microsoft-graph-app-manifest#web-attribute
	webInfo, err := convert.JsonToDict(newWebApplication(app.GetWeb()))
	if err != nil {
		return nil, err
	}
	// https://learn.microsoft.com/en-us/entra/identity-platform/reference-microsoft-graph-app-manifest#spa-attribute
	spaInfo, err := convert.JsonToDict(newSpaApplication(app.GetSpa()))
	if err != nil {
		return nil, err
	}
	certification, err := convert.JsonToDict(newCertificationable(app.GetCertification()))
	if err != nil {
		return nil, err
	}
	optionalClaims, err := convert.JsonToDict(newOptionalClaimsable(app.GetOptionalClaims()))
	if err != nil {
		return nil, err
	}
	servicePrincipalLockConfiguration, err := convert.JsonToDict(newServicePrincipalLockConfiguration(app.GetServicePrincipalLockConfiguration()))
	if err != nil {
		return nil, err
	}
	requestSignatureVerification, err := convert.JsonToDict(newRequestSignatureVerification(app.GetRequestSignatureVerification()))
	if err != nil {
		return nil, err
	}
	parentalControlSettings, err := convert.JsonToDict(newParentalControlSettings(app.GetParentalControlSettings()))
	if err != nil {
		return nil, err
	}
	publicClient, err := convert.JsonToDict(newPublicClientApplication(app.GetPublicClient()))
	if err != nil {
		return nil, err
	}
	requiredResourceAccess, err := convert.JsonToDictSlice(newRequiredResourceAccessList(app.GetRequiredResourceAccess()))
	if err != nil {
		return nil, err
	}

	var nativeAuthenticationApisEnabled *string
	if app.GetNativeAuthenticationApisEnabled() != nil {
		val := app.GetNativeAuthenticationApisEnabled().String()
		nativeAuthenticationApisEnabled = &val
	}

	mqlAppRoleList := []any{}
	appRoles := app.GetAppRoles()
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

	mqlResource, err := CreateResource(runtime, "microsoft.application",
		map[string]*llx.RawData{
			"__id":                              llx.StringDataPtr(app.GetId()),
			"id":                                llx.StringDataPtr(app.GetId()),
			"appId":                             llx.StringDataPtr(app.GetAppId()),
			"applicationTemplateId":             llx.StringDataPtr(app.GetApplicationTemplateId()),
			"createdAt":                         llx.TimeDataPtr(app.GetCreatedDateTime()),
			"disabledByMicrosoftStatus":         llx.StringDataPtr(app.GetDisabledByMicrosoftStatus()),
			"groupMembershipClaims":             llx.StringDataPtr(app.GetGroupMembershipClaims()),
			"name":                              llx.StringDataPtr(app.GetDisplayName()),
			"description":                       llx.StringDataPtr(app.GetDescription()),
			"notes":                             llx.StringDataPtr(app.GetNotes()),
			"publisherDomain":                   llx.StringDataPtr(app.GetPublisherDomain()),
			"signInAudience":                    llx.StringDataPtr(app.GetSignInAudience()),
			"tags":                              llx.ArrayData(convert.SliceAnyToInterface(app.GetTags()), types.String),
			"identifierUris":                    llx.ArrayData(convert.SliceAnyToInterface(app.GetIdentifierUris()), types.String),
			"info":                              llx.DictData(info),
			"api":                               llx.DictData(apiInfo),
			"web":                               llx.DictData(webInfo),
			"spa":                               llx.DictData(spaInfo),
			"secrets":                           llx.ArrayData(secrets, types.Resource("microsoft.passwordCredential")),
			"certificates":                      llx.ArrayData(certificates, types.Resource("microsoft.keyCredential")),
			"isDeviceOnlyAuthSupported":         llx.BoolDataPtr(app.GetIsDeviceOnlyAuthSupported()),
			"isFallbackPublicClient":            llx.BoolDataPtr(app.GetIsFallbackPublicClient()),
			"nativeAuthenticationApisEnabled":   llx.StringDataPtr(nativeAuthenticationApisEnabled),
			"serviceManagementReference":        llx.StringDataPtr(app.GetServiceManagementReference()),
			"tokenEncryptionKeyId":              llx.StringDataPtr(newUuidString(app.GetTokenEncryptionKeyId())),
			"samlMetadataUrl":                   llx.StringDataPtr(app.GetSamlMetadataUrl()),
			"defaultRedirectUri":                llx.StringDataPtr(app.GetDefaultRedirectUri()),
			"certification":                     llx.DictData(certification),
			"optionalClaims":                    llx.DictData(optionalClaims),
			"servicePrincipalLockConfiguration": llx.DictData(servicePrincipalLockConfiguration),
			"requestSignatureVerification":      llx.DictData(requestSignatureVerification),
			"parentalControlSettings":           llx.DictData(parentalControlSettings),
			"publicClient":                      llx.DictData(publicClient),
			"appRoles":                          llx.ArrayData(mqlAppRoleList, types.Resource("microsoft.application.role")),
			"requiredResourceAccess":            llx.ArrayData(requiredResourceAccess, types.Dict),
		})
	if err != nil {
		return nil, err
	}
	return mqlResource.(*mqlMicrosoftApplication), nil
}

func initMicrosoftApplication(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	var appId string

	raw, ok := args["id"]
	if ok && len(args) < 3 {
		appId = raw.Value.(string)
	}
	if appId == "" {
		// lookup by name
		raw, ok := args["name"]
		if ok && len(args) == 1 {
			name := raw.Value.(string)
			id, err := fetchApplicationIdByName(runtime, name)
			if err != nil {
				return nil, nil, err
			}
			appId = *id
		}
	}
	if appId == "" {
		return nil, nil, errors.New("need name or id to fetch application")
	}

	ctx := context.Background()

	conn := runtime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, nil, err
	}
	// https://graph.microsoft.com/v1.0/applications/{application-id}
	app, err := graphClient.Applications().ByApplicationId(appId).Get(ctx, &applications.ApplicationItemRequestBuilderGetRequestConfiguration{})
	if err != nil {
		return nil, nil, transformError(err)
	}
	mqlMsApp, err := newMqlMicrosoftApplication(runtime, app)
	if err != nil {
		return nil, nil, err
	}

	return nil, mqlMsApp, nil
}

func fetchApplicationIdByName(runtime *plugin.Runtime, name string) (*string, error) {
	conn := runtime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	filter := odataEqFilter("displayName", name)
	ctx := context.Background()
	resp, err := graphClient.Applications().Get(ctx, &applications.ApplicationsRequestBuilderGetRequestConfiguration{
		QueryParameters: &applications.ApplicationsRequestBuilderGetQueryParameters{
			Filter: &filter,
		},
	})
	if err != nil {
		return nil, transformError(err)
	}

	val := resp.GetValue()
	if len(val) == 0 {
		return nil, errors.New("application not found")
	}

	applicationId := val[0].GetId()
	if applicationId == nil {
		return nil, errors.New("application id not found")
	}
	return applicationId, nil
}

func fetchApplicationById(runtime *plugin.Runtime, id string) (models.Applicationable, error) {
	conn := runtime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	// https://graph.microsoft.com/v1.0/applications/{application-id}
	app, err := graphClient.Applications().ByApplicationId(id).Get(ctx, &applications.ApplicationItemRequestBuilderGetRequestConfiguration{})
	if err != nil {
		return nil, transformError(err)
	}
	return app, nil
}

// hasExpiredCredentials returns true if any of the credentials of the application are expired
func (a *mqlMicrosoftApplication) hasExpiredCredentials() (bool, error) {
	certificates := a.GetCertificates()
	for _, val := range certificates.Data {
		cert := val.(*mqlMicrosoftKeyCredential)
		if cert.GetExpired().Data {
			return true, nil
		}
	}

	secrets := a.GetSecrets()
	for _, val := range secrets.Data {
		secret := val.(*mqlMicrosoftPasswordCredential)
		if secret.GetExpired().Data {
			return true, nil
		}
	}
	return false, nil
}

func (a *mqlMicrosoftApplication) servicePrincipal() (*mqlMicrosoftServiceprincipal, error) {
	// Resolve from the tenant's service principal list rather than running one
	// filtered Graph query per application. microsoft.serviceprincipals is a
	// single paginated call and is memoized on the microsoft resource, so the
	// whole set costs one fetch however many applications ask.
	//
	// Measured on a 72-application tenant: reading servicePrincipal for every
	// application took 123s through the per-application filter and 4s to list
	// the applications alone. Graph throttles on request volume, so the cost
	// grows faster than linearly on a tenant with thousands of registrations.
	msResource, err := CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	principals := msResource.(*mqlMicrosoft).GetServiceprincipals()
	if principals.Error != nil {
		return nil, principals.Error
	}

	wantAppId := a.GetAppId().Data
	if wantAppId != "" {
		for i := range principals.Data {
			sp, ok := principals.Data[i].(*mqlMicrosoftServiceprincipal)
			if !ok {
				continue
			}
			if sp.AppId.Data == wantAppId {
				return sp, nil
			}
		}
	}

	// Not every application registration has a service principal in this
	// tenant -- a multi-tenant app nobody has consented to has none -- so this
	// is a legitimate empty state rather than a failure. The field has to be
	// marked set-and-null before returning nil: without it the runtime does not
	// know the field was resolved, and the query fails for an application whose
	// only problem is that it is exactly what it claims to be.
	a.ServicePrincipal.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (a *mqlMicrosoftApplication) owners() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)

	msResource, err := a.MqlRuntime.CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	mqlMicrosoftResource := msResource.(*mqlMicrosoft)

	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	// Select the same user fields used by initMicrosoftUser so accessing
	// owner.displayName/mail/etc. is served from the owners response instead
	// of triggering one Graph call per owner.
	resp, err := graphClient.Applications().ByApplicationId(a.GetId().Data).Owners().Get(ctx, &applications.ItemOwnersRequestBuilderGetRequestConfiguration{
		QueryParameters: &applications.ItemOwnersRequestBuilderGetQueryParameters{
			Select: userSelectFields,
		},
	})
	if err != nil {
		return nil, transformError(err)
	}
	owners, err := iterate[models.DirectoryObjectable](ctx, resp, graphClient.GetAdapter(), models.CreateDirectoryObjectCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, user := range userOwners(owners) {
		// if the user is already indexed, we can reuse it
		if userResource, ok := mqlMicrosoftResource.userById(*user.GetId()); ok {
			res = append(res, userResource)
			continue
		}

		// Build the resource from the data already on the response, which
		// avoids a second Graph round-trip via initMicrosoftUser when callers
		// read common user fields.
		newUser, err := newMqlMicrosoftUser(a.MqlRuntime, user)
		if err != nil {
			return nil, err
		}
		mqlMicrosoftResource.indexUser(newUser)
		res = append(res, newUser)
	}
	return res, nil
}

// userOwners returns the owners that are users. An application can also be
// owned by a service principal, which is common for apps created by
// automation. Such an owner is not a microsoft.user: resolving its id as one
// asks Graph for /users/{id}, which fails with not found and would fail the
// whole owners list, so it is skipped.
func userOwners(owners []models.DirectoryObjectable) []models.Userable {
	res := make([]models.Userable, 0, len(owners))
	for _, owner := range owners {
		if owner == nil || owner.GetId() == nil {
			continue
		}
		user, ok := owner.(models.Userable)
		if !ok {
			odataType := ""
			if t := owner.GetOdataType(); t != nil {
				odataType = *t
			}
			log.Debug().Str("owner", *owner.GetId()).Str("type", odataType).Msg("skipping application owner that is not a user")
			continue
		}
		res = append(res, user)
	}
	return res
}

// newMqlMicrosoftKeyCredential creates a new mqlMicrosoftKeyCredential resource
func newMqlMicrosoftKeyCredential(runtime *plugin.Runtime, app models.KeyCredentialable) (*mqlMicrosoftKeyCredential, error) {
	endDate := app.GetEndDateTime()
	expired := true
	if endDate != nil {
		expired = endDate.Before(time.Now())
	}

	mqlResource, err := CreateResource(runtime, "microsoft.keyCredential",
		map[string]*llx.RawData{
			"__id":          llx.StringData(app.GetKeyId().String()),
			"keyId":         llx.StringData(app.GetKeyId().String()),
			"description":   llx.StringDataPtr(app.GetDisplayName()),
			"usage":         llx.StringDataPtr(app.GetUsage()),
			"thumbprint":    llx.StringData(base64.StdEncoding.EncodeToString(app.GetCustomKeyIdentifier())),
			"type":          llx.StringDataPtr(app.GetTypeEscaped()),
			"expires":       llx.TimeDataPtr(endDate),
			"expired":       llx.BoolData(expired),
			"startDateTime": llx.TimeDataPtr(app.GetStartDateTime()),
		})
	if err != nil {
		return nil, err
	}
	return mqlResource.(*mqlMicrosoftKeyCredential), nil
}

// newMqlMicrosoftPasswordCredential creates a new mqlMicrosoftPasswordCredential resource
func newMqlMicrosoftPasswordCredential(runtime *plugin.Runtime, app models.PasswordCredentialable) (*mqlMicrosoftPasswordCredential, error) {
	endDate := app.GetEndDateTime()
	expired := true
	if endDate != nil {
		expired = endDate.Before(time.Now())
	}

	mqlResource, err := CreateResource(runtime, "microsoft.passwordCredential",
		map[string]*llx.RawData{
			"__id":          llx.StringData(app.GetKeyId().String()),
			"keyId":         llx.StringData(app.GetKeyId().String()),
			"description":   llx.StringDataPtr(app.GetDisplayName()),
			"hint":          llx.StringDataPtr(app.GetHint()),
			"expires":       llx.TimeDataPtr(endDate),
			"expired":       llx.BoolData(expired),
			"startDateTime": llx.TimeDataPtr(app.GetStartDateTime()),
		})
	if err != nil {
		return nil, err
	}
	return mqlResource.(*mqlMicrosoftPasswordCredential), nil
}
