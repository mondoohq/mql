// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/oauth2permissiongrants"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// oauth2PermissionGrants lists every delegated permission grant consented
// across the tenant.
// Requires the Directory.Read.All application permission.
// see https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list
func (a *mqlMicrosoft) oauth2PermissionGrants() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	// resolve the service principal collection first so the app-name index is
	// populated for the client and resource display names below
	if sps := a.GetServiceprincipals(); sps.Error != nil {
		return nil, sps.Error
	}

	top := int32(999)
	resp, err := graphClient.Oauth2PermissionGrants().Get(ctx, &oauth2permissiongrants.Oauth2PermissionGrantsRequestBuilderGetRequestConfiguration{
		QueryParameters: &oauth2permissiongrants.Oauth2PermissionGrantsRequestBuilderGetQueryParameters{
			Top: &top,
		},
	})
	if err != nil {
		return nil, transformError(err)
	}

	grants, err := iterate[models.OAuth2PermissionGrantable](ctx, resp, graphClient.GetAdapter(), models.CreateOAuth2PermissionGrantCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, transformError(err)
	}

	res := []any{}
	for _, grant := range grants {
		clientId := convert.ToValue(grant.GetClientId())
		resourceId := convert.ToValue(grant.GetResourceId())
		clientName, _ := a.appName(clientId)
		resourceName, _ := a.appName(resourceId)

		scopes := []any{}
		if grant.GetScope() != nil {
			for scope := range strings.FieldsSeq(*grant.GetScope()) {
				scopes = append(scopes, scope)
			}
		}

		mqlGrant, err := CreateResource(a.MqlRuntime, "microsoft.oauth2PermissionGrant", map[string]*llx.RawData{
			"__id":         llx.StringDataPtr(grant.GetId()),
			"id":           llx.StringDataPtr(grant.GetId()),
			"clientId":     llx.StringData(clientId),
			"clientName":   llx.StringData(clientName),
			"resourceId":   llx.StringData(resourceId),
			"resourceName": llx.StringData(resourceName),
			"consentType":  llx.StringDataPtr(grant.GetConsentType()),
			"principalId":  llx.StringDataPtr(grant.GetPrincipalId()),
			"scopes":       llx.ArrayData(scopes, types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGrant)
	}
	return res, nil
}

// client resolves the service principal of the application this grant authorizes.
func (g *mqlMicrosoftOauth2PermissionGrant) client() (*mqlMicrosoftServiceprincipal, error) {
	return g.servicePrincipalByID(g.ClientId.Data, &g.Client)
}

// resource resolves the service principal of the API the grant provides access to.
func (g *mqlMicrosoftOauth2PermissionGrant) resource() (*mqlMicrosoftServiceprincipal, error) {
	return g.servicePrincipalByID(g.ResourceId.Data, &g.Resource)
}

func (g *mqlMicrosoftOauth2PermissionGrant) servicePrincipalByID(id string, field *plugin.TValue[*mqlMicrosoftServiceprincipal]) (*mqlMicrosoftServiceprincipal, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	sp, err := NewResource(g.MqlRuntime, "microsoft.serviceprincipal", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return sp.(*mqlMicrosoftServiceprincipal), nil
}

// principal resolves the user who consented, when consentType is `Principal`.
func (g *mqlMicrosoftOauth2PermissionGrant) principal() (*mqlMicrosoftUser, error) {
	principalId := g.PrincipalId.Data
	if principalId == "" {
		g.Principal.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	user, err := NewResource(g.MqlRuntime, "microsoft.user", map[string]*llx.RawData{
		"id": llx.StringData(principalId),
	})
	if err != nil {
		return nil, err
	}
	return user.(*mqlMicrosoftUser), nil
}
