// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

type mqlMongodbatlasFederationConfigInternal struct {
	cacheIdpID string
}

func (r *mqlMongodbatlas) federationSettings() (*mqlMongodbatlasFederationConfig, error) {
	oid, err := orgID(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	fs, httpResp, err := atlasClient(r.MqlRuntime).FederatedAuthenticationAPI.GetFederationSettings(context.Background(), oid).Execute()
	if err != nil {
		// An organization without federation configured returns 404, and a
		// credential without org-owner access returns 401/403; both degrade to
		// null rather than failing the scan.
		if isAccessDenied(httpResp) || (httpResp != nil && httpResp.StatusCode == http.StatusNotFound) {
			r.FederationSettings.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	res, err := CreateResource(r.MqlRuntime, "mongodbatlas.federationConfig", map[string]*llx.RawData{
		"__id":                   llx.StringData("mongodbatlas.federationConfig/" + fs.GetId()),
		"id":                     llx.StringData(fs.GetId()),
		"identityProviderStatus": llx.StringData(fs.GetIdentityProviderStatus()),
		"hasRoleMappings":        llx.BoolData(fs.GetHasRoleMappings()),
		"federatedDomains":       llx.ArrayData(strSlice(fs.GetFederatedDomains()), types.String),
	})
	if err != nil {
		return nil, err
	}
	cfg := res.(*mqlMongodbatlasFederationConfig)
	cfg.cacheIdpID = fs.GetIdentityProviderId()
	return cfg, nil
}

// newMqlMongodbatlasIdentityProvider maps an identity provider to its resource,
// shared by the identityProviders list and the connected-provider accessor.
func newMqlMongodbatlasIdentityProvider(runtime *plugin.Runtime, fedID string, idp admin.FederationIdentityProvider) (*mqlMongodbatlasIdentityProvider, error) {
	res, err := CreateResource(runtime, "mongodbatlas.identityProvider", map[string]*llx.RawData{
		"__id":                       llx.StringData("mongodbatlas.identityProvider/" + fedID + "/" + idp.GetId()),
		"id":                         llx.StringData(idp.GetId()),
		"displayName":                llx.StringData(idp.GetDisplayName()),
		"description":                llx.StringData(idp.GetDescription()),
		"protocol":                   llx.StringData(idp.GetProtocol()),
		"idpType":                    llx.StringData(idp.GetIdpType()),
		"status":                     llx.StringData(idp.GetStatus()),
		"issuerUri":                  llx.StringData(idp.GetIssuerUri()),
		"associatedDomains":          llx.ArrayData(strSlice(idp.GetAssociatedDomains()), types.String),
		"ssoUrl":                     llx.StringData(idp.GetSsoUrl()),
		"ssoDebugEnabled":            llx.BoolData(idp.GetSsoDebugEnabled()),
		"requestBinding":             llx.StringData(idp.GetRequestBinding()),
		"responseSignatureAlgorithm": llx.StringData(idp.GetResponseSignatureAlgorithm()),
		"clientId":                   llx.StringData(idp.GetClientId()),
		"authorizationType":          llx.StringData(idp.GetAuthorizationType()),
		"groupsClaim":                llx.StringData(idp.GetGroupsClaim()),
		"userClaim":                  llx.StringData(idp.GetUserClaim()),
		"requestedScopes":            llx.ArrayData(strSlice(idp.GetRequestedScopes()), types.String),
		"createdAt":                  llx.TimeDataPtr(timePtr(idp.GetCreatedAt())),
		"updatedAt":                  llx.TimeDataPtr(timePtr(idp.GetUpdatedAt())),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMongodbatlasIdentityProvider), nil
}

// identityProvider resolves the identity provider connected to the organization,
// the anchor of the SSO posture. Null when no provider is connected.
func (r *mqlMongodbatlasFederationConfig) identityProvider() (*mqlMongodbatlasIdentityProvider, error) {
	if r.cacheIdpID == "" {
		r.IdentityProvider.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	fedID := r.Id.Data
	idp, httpResp, err := atlasClient(r.MqlRuntime).FederatedAuthenticationAPI.GetIdentityProvider(context.Background(), fedID, r.cacheIdpID).Execute()
	if err != nil {
		if isAccessDenied(httpResp) || (httpResp != nil && httpResp.StatusCode == http.StatusNotFound) {
			r.IdentityProvider.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return newMqlMongodbatlasIdentityProvider(r.MqlRuntime, fedID, *idp)
}

func (r *mqlMongodbatlasFederationConfig) identityProviders() ([]any, error) {
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()
	fedID := r.Id.Data

	out := []any{}
	for page := 1; ; page++ {
		resp, _, err := client.FederatedAuthenticationAPI.ListIdentityProviders(ctx, fedID).ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			return nil, err
		}
		results := resp.GetResults()
		for i := range results {
			res, err := newMqlMongodbatlasIdentityProvider(r.MqlRuntime, fedID, results[i])
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
		if len(results) < pageSize {
			break
		}
	}
	return out, nil
}
