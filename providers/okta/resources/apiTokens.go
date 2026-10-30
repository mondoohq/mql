// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/okta/connection"
)

// mqlOktaApiTokenInternal caches the owning user's id so the typed user()
// accessor can resolve without exposing a deprecated public field.
type mqlOktaApiTokenInternal struct {
	cacheUserId string
}

// apiTokens lists API tokens for the org. Requires Super Admin privileges
// (the /api/v1/api-tokens endpoint).
func (o *mqlOkta) apiTokens() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)

	ctx := context.Background()
	apiSupplement := conn.ApiExtension()

	tokens, err := apiSupplement.ListApiTokens(ctx, queryLimit)
	if err != nil {
		return nil, err
	}

	list := []any{}
	for _, t := range tokens {
		r, err := CreateResource(o.MqlRuntime, "okta.api.token", map[string]*llx.RawData{
			"id":          llx.StringData(t.Id),
			"name":        llx.StringData(t.Name),
			"clientName":  llx.StringData(t.ClientName),
			"created":     llx.TimeDataPtr(t.Created),
			"expiresAt":   llx.TimeDataPtr(t.ExpiresAt),
			"lastUpdated": llx.TimeDataPtr(t.LastUpdated),
			"tokenWindow": llx.StringData(t.TokenWindow),
		})
		if err != nil {
			return nil, err
		}
		mqlToken := r.(*mqlOktaApiToken)
		mqlToken.cacheUserId = t.UserId
		list = append(list, mqlToken)
	}
	return list, nil
}

func (o *mqlOktaApiToken) id() (string, error) {
	return "okta.api.token/" + o.Id.Data, o.Id.Error
}

// user resolves the typed user this API token was issued for. The runtime
// caches okta.user instances keyed by id, so repeated lookups across api
// tokens (and other resources) reuse a single GetUser call.
func (o *mqlOktaApiToken) user() (*mqlOktaUser, error) {
	if o.cacheUserId == "" {
		o.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	r, err := NewResource(o.MqlRuntime, "okta.user", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheUserId),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOktaUser), nil
}
