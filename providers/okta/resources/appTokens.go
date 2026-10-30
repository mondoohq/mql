// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/okta/connection"
	"go.mondoo.com/mql/types"
)

type mqlOktaApplicationTokenInternal struct {
	cacheUserID string
}

func (a *mqlOktaApplication) tokens() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.OktaConnection)
	ctx := context.Background()
	appID := a.Id.Data

	slice, resp, err := conn.Client().ApplicationTokensAPI.
		ListOAuth2TokensForApplication(ctx, appID).Limit(queryLimit).Execute()
	if err != nil {
		// Only OAuth 2.0 clients can hold refresh tokens. Okta rejects the
		// request with a 400 for any other application (a bookmark or SAML
		// app), which is a statement about the app's type rather than a
		// failure. The request carries no caller-supplied input beyond the app
		// id, so a 400 here has no other meaning.
		if isOktaFeatureUnavailable(resp, err) || isOktaStatus(resp, http.StatusBadRequest) {
			return nil, nil
		}
		return nil, err
	}

	tokens, err := oktaCollectPages(slice, resp)
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(tokens))
	for i := range tokens {
		r, err := newMqlOktaApplicationToken(a.MqlRuntime, appID, &tokens[i])
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

// newMqlOktaApplicationToken maps one outstanding refresh token. The token id
// is unique only within its application, so the cache key is qualified by the
// app the token was read from.
func newMqlOktaApplicationToken(runtime *plugin.Runtime, appID string, entry *okta.OAuth2RefreshToken) (*mqlOktaApplicationToken, error) {
	tokenID := oktaStr(entry.Id)

	r, err := CreateResource(runtime, "okta.application.token", map[string]*llx.RawData{
		"__id":        llx.StringData("okta.application.token/" + appID + "/" + tokenID),
		"id":          llx.StringData(tokenID),
		"status":      llx.StringData(oktaStr(entry.Status)),
		"created":     llx.TimeDataPtr(entry.Created),
		"expiresAt":   llx.TimeDataPtr(entry.ExpiresAt),
		"lastUpdated": llx.TimeDataPtr(entry.LastUpdated),
		"issuer":      llx.StringData(oktaStr(entry.Issuer)),
		"clientId":    llx.StringData(oktaStr(entry.ClientId)),
		"scopes":      llx.ArrayData(convert.SliceAnyToInterface(entry.Scopes), types.String),
	})
	if err != nil {
		return nil, err
	}

	token := r.(*mqlOktaApplicationToken)
	token.cacheUserID = oktaStr(entry.UserId)
	return token, nil
}

func (a *mqlOktaApplicationToken) user() (*mqlOktaUser, error) {
	return resolveOktaUserRef(a.MqlRuntime, a.cacheUserID, &a.User)
}
