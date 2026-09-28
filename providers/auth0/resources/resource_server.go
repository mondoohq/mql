// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/auth0/go-auth0"
	"github.com/auth0/go-auth0/management"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/auth0/connection"
	"go.mondoo.com/mql/types"
)

// resourceServers lists every API (resource server) registered in the tenant.
func (a *mqlAuth0) resourceServers() ([]any, error) {
	conn := a.conn()
	client := conn.Client()

	var all []any
	page := 0
	for {
		list, err := client.ResourceServer.List(context.Background(),
			management.Page(page),
			management.PerPage(50),
			management.IncludeTotals(true),
		)
		if err != nil {
			return nil, err
		}
		for _, rs := range list.ResourceServers {
			r, err := newMqlAuth0ResourceServer(a.MqlRuntime, rs)
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

// newMqlAuth0ResourceServer maps a single SDK resource server to its MQL resource.
func newMqlAuth0ResourceServer(runtime *plugin.Runtime, rs *management.ResourceServer) (plugin.Resource, error) {
	scopes := map[string]any{}
	if rs.Scopes != nil {
		for _, s := range *rs.Scopes {
			key := auth0.StringValue(s.Value)
			if key == "" {
				continue
			}
			scopes[key] = auth0.StringValue(s.Description)
		}
	}

	var popMechanism, popRequiredFor *string
	var popRequired *bool
	if rs.ProofOfPossession != nil {
		popMechanism = rs.ProofOfPossession.Mechanism
		popRequired = rs.ProofOfPossession.Required
		popRequiredFor = rs.ProofOfPossession.RequiredFor
	}

	userPolicy, clientPolicy, anonymousUserPolicy := subjectTypePolicies(rs.SubjectTypeAuthorization)

	r, err := CreateResource(runtime, "auth0.resourceServer", map[string]*llx.RawData{
		"id":                  llx.StringDataPtr(rs.ID),
		"name":                llx.StringDataPtr(rs.Name),
		"identifier":          llx.StringDataPtr(rs.Identifier),
		"signingAlgorithm":    llx.StringDataPtr(rs.SigningAlgorithm),
		"tokenLifetime":       llx.IntDataPtr(rs.TokenLifetime),
		"tokenLifetimeForWeb": llx.IntDataPtr(rs.TokenLifetimeForWeb),
		"tokenDialect":        llx.StringDataPtr(rs.TokenDialect),
		"enforcePolicies":     llx.BoolDataPtr(rs.EnforcePolicies),
		"allowOfflineAccess":  llx.BoolDataPtr(rs.AllowOfflineAccess),
		"skipConsentForVerifiableFirstPartyClients": llx.BoolDataPtr(rs.SkipConsentForVerifiableFirstPartyClients),
		"isSystem":                              llx.BoolDataPtr(rs.IsSystem),
		"scopes":                                llx.MapData(scopes, types.String),
		"proofOfPossessionMechanism":            llx.StringDataPtr(popMechanism),
		"proofOfPossessionRequired":             llx.BoolDataPtr(popRequired),
		"proofOfPossessionRequiredFor":          llx.StringDataPtr(popRequiredFor),
		"tokenLifetimeForAnonymousAccessTokens": llx.IntDataPtr(rs.TokenLifetimeForAnonymousAccessTokens),
		"userPolicy":                            llx.StringDataPtr(userPolicy),
		"clientPolicy":                          llx.StringDataPtr(clientPolicy),
		"anonymousUserPolicy":                   llx.StringDataPtr(anonymousUserPolicy),
		"accessTokenCustomClaims":               accessTokenCustomClaims(rs.AccessToken),
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// initAuth0ResourceServer resolves an API by its ID or identifier (audience) on
// demand, for typed references (e.g. auth0.clientGrant.resourceServer) and
// direct lookups. The Auth0 API accepts either value at the same endpoint.
func initAuth0ResourceServer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	var key string
	if idArg, ok := args["id"]; ok {
		if v, ok := idArg.Value.(string); ok {
			key = v
		}
	}
	if key == "" {
		if idArg, ok := args["identifier"]; ok {
			if v, ok := idArg.Value.(string); ok {
				key = v
			}
		}
	}
	if key == "" {
		return nil, nil, fmt.Errorf("auth0.resourceServer requires an id or identifier argument")
	}

	conn := runtime.Connection.(*connection.Auth0Connection)
	rs, err := conn.Client().ResourceServer.Read(context.Background(), key)
	if err != nil {
		return nil, nil, fmt.Errorf("auth0.resourceServer %q not found: %w", key, err)
	}

	res, err := newMqlAuth0ResourceServer(runtime, rs)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

func (r *mqlAuth0ResourceServer) id() (string, error) {
	return "auth0.resourceServer/" + r.Id.Data, nil
}

// subjectTypePolicies returns the user, client, and anonymous-user
// authorization policies, each nil when the API did not report it.
func subjectTypePolicies(sta *management.ResourceServerSubjectTypeAuthorization) (user, client, anonymousUser *string) {
	if sta == nil {
		return nil, nil, nil
	}
	if sta.User != nil {
		user = sta.User.Policy
	}
	if sta.Client != nil {
		client = sta.Client.Policy
	}
	if sta.AnonymousUser != nil {
		anonymousUser = sta.AnonymousUser.Policy
	}
	return user, client, anonymousUser
}

// accessTokenCustomClaims maps the access token custom claims to a claim name
// to expression map, or null when no claims mapping is configured.
func accessTokenCustomClaims(at *management.ResourceServerAccessToken) *llx.RawData {
	if at == nil || at.ClaimsMapping == nil || at.ClaimsMapping.CustomClaims == nil {
		return llx.NilData
	}
	claims := map[string]any{}
	for _, c := range *at.ClaimsMapping.CustomClaims {
		if c.Name == nil || *c.Name == "" {
			continue
		}
		claims[*c.Name] = auth0.StringValue(c.Expression)
	}
	return llx.MapData(claims, types.String)
}
