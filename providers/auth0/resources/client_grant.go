// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/auth0/go-auth0/management"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// mqlAuth0ClientGrantInternal caches the raw client ID so the client accessor
// can resolve it into a typed auth0.client reference on demand.
type mqlAuth0ClientGrantInternal struct {
	cacheClientId *string
}

// clientGrants lists every machine-to-machine client grant in the tenant.
func (a *mqlAuth0) clientGrants() ([]any, error) {
	conn := a.conn()
	client := conn.Client()

	var all []any
	page := 0
	for {
		list, err := client.ClientGrant.List(context.Background(),
			management.Page(page),
			management.PerPage(50),
			management.IncludeTotals(true),
		)
		if err != nil {
			return nil, err
		}
		for _, g := range list.ClientGrants {
			r, err := newMqlAuth0ClientGrant(a.MqlRuntime, g)
			if err != nil {
				return nil, err
			}
			all = append(all, r)
		}
		if !list.HasNext() {
			break
		}
		page++
	}
	return all, nil
}

// newMqlAuth0ClientGrant maps a single SDK client grant to its MQL resource,
// caching the client ID for the typed client accessor.
func newMqlAuth0ClientGrant(runtime *plugin.Runtime, g *management.ClientGrant) (plugin.Resource, error) {
	r, err := CreateResource(runtime, "auth0.clientGrant", map[string]*llx.RawData{
		"id":                   llx.StringDataPtr(g.ID),
		"audience":             llx.StringDataPtr(g.Audience),
		"scopes":               llx.ArrayData(strList(g.Scope), types.String),
		"allowAllScopes":       llx.BoolDataPtr(g.AllowAllScopes),
		"allowAnyOrganization": llx.BoolDataPtr(g.AllowAnyOrganization),
		"organizationUsage":    llx.StringDataPtr(g.OrganizationUsage),
		"subjectType":          llx.StringDataPtr(g.SubjectType),
	})
	if err != nil {
		return nil, err
	}
	mqlGrant := r.(*mqlAuth0ClientGrant)
	mqlGrant.cacheClientId = g.ClientID
	return r, nil
}

// client resolves the application this grant authorizes into a typed
// auth0.client reference.
func (g *mqlAuth0ClientGrant) client() (*mqlAuth0Client, error) {
	if g.cacheClientId == nil || *g.cacheClientId == "" {
		g.Client.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(g.MqlRuntime, "auth0.client",
		map[string]*llx.RawData{"id": llx.StringDataPtr(g.cacheClientId)})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAuth0Client), nil
}

// resourceServer resolves the API the grant targets, keyed by its audience
// (the resource server identifier), into a typed auth0.resourceServer reference.
func (g *mqlAuth0ClientGrant) resourceServer() (*mqlAuth0ResourceServer, error) {
	audience := g.Audience.Data
	if audience == "" {
		g.ResourceServer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(g.MqlRuntime, "auth0.resourceServer",
		map[string]*llx.RawData{"identifier": llx.StringData(audience)})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAuth0ResourceServer), nil
}

func (g *mqlAuth0ClientGrant) id() (string, error) {
	return "auth0.clientGrant/" + g.Id.Data, nil
}
