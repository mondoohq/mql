// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/auth0/go-auth0/management"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/auth0/connection"
	"go.mondoo.com/mql/types"
)

// clients lists every application (OAuth/OIDC client) registered in the tenant.
func (a *mqlAuth0) clients() ([]any, error) {
	conn := a.conn()
	client := conn.Client()

	var all []any
	page := 0
	for {
		list, err := client.Client.List(context.Background(),
			management.Page(page),
			management.PerPage(50),
			management.IncludeTotals(true),
		)
		if err != nil {
			return nil, err
		}
		for _, c := range list.Clients {
			r, err := newMqlAuth0Client(a.MqlRuntime, c)
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

// newMqlAuth0Client maps a single SDK client to its MQL resource.
func newMqlAuth0Client(runtime *plugin.Runtime, c *management.Client) (plugin.Resource, error) {
	jwt := map[string]any{}
	if c.JWTConfiguration != nil {
		if c.JWTConfiguration.Algorithm != nil {
			jwt["alg"] = *c.JWTConfiguration.Algorithm
		}
		if c.JWTConfiguration.LifetimeInSeconds != nil {
			jwt["lifetimeInSeconds"] = *c.JWTConfiguration.LifetimeInSeconds
		}
	}

	meta := map[string]any{}
	if c.ClientMetadata != nil {
		for k, v := range *c.ClientMetadata {
			if v == nil {
				continue
			}
			meta[k] = fmt.Sprintf("%v", v)
		}
	}

	var rotationType, expirationType *string
	var leeway, tokenLifetime, idleTokenLifetime *int
	if c.RefreshToken != nil {
		rotationType = c.RefreshToken.RotationType
		expirationType = c.RefreshToken.ExpirationType
		leeway = c.RefreshToken.Leeway
		tokenLifetime = c.RefreshToken.TokenLifetime
		idleTokenLifetime = c.RefreshToken.IdleTokenLifetime
	}

	authMethods := []any{}
	if am := c.ClientAuthenticationMethods; am != nil {
		if am.PrivateKeyJWT != nil {
			authMethods = append(authMethods, "private_key_jwt")
		}
		if am.TLSClientAuth != nil {
			authMethods = append(authMethods, "tls_client_auth")
		}
		if am.SelfSignedTLSClientAuth != nil {
			authMethods = append(authMethods, "self_signed_tls_client_auth")
		}
	}

	myOrg, err := newMqlAuth0ClientMyOrganization(runtime, c.ClientID, c.MyOrganizationConfiguration)
	if err != nil {
		return nil, err
	}

	r, err := CreateResource(runtime, "auth0.client", map[string]*llx.RawData{
		"id":                         llx.StringDataPtr(c.ClientID),
		"name":                       llx.StringDataPtr(c.Name),
		"description":                llx.StringDataPtr(c.Description),
		"appType":                    llx.StringDataPtr(c.AppType),
		"isFirstParty":               llx.BoolDataPtr(c.IsFirstParty),
		"oidcConformant":             llx.BoolDataPtr(c.OIDCConformant),
		"callbacks":                  llx.ArrayData(strList(c.Callbacks), types.String),
		"allowedLogoutUrls":          llx.ArrayData(strList(c.AllowedLogoutURLs), types.String),
		"allowedOrigins":             llx.ArrayData(strList(c.AllowedOrigins), types.String),
		"webOrigins":                 llx.ArrayData(strList(c.WebOrigins), types.String),
		"grantTypes":                 llx.ArrayData(strList(c.GrantTypes), types.String),
		"tokenEndpointAuthMethod":    llx.StringDataPtr(c.TokenEndpointAuthMethod),
		"refreshTokenRotationType":   llx.StringDataPtr(rotationType),
		"refreshTokenExpirationType": llx.StringDataPtr(expirationType),
		"refreshTokenLeeway":         llx.IntDataPtr(leeway),
		"refreshTokenLifetime":       llx.IntDataPtr(tokenLifetime),
		"refreshTokenIdleLifetime":   llx.IntDataPtr(idleTokenLifetime),
		"ssoDisabled":                llx.BoolDataPtr(c.SSODisabled),
		"crossOriginAuth":            llx.BoolDataPtr(c.CrossOriginAuth),
		"initiateLoginUri":           llx.StringDataPtr(c.InitiateLoginURI),
		"jwtConfiguration":           llx.DictData(jwt),
		"clientMetadata":             llx.MapData(meta, types.String),
		"authenticationMethods":      llx.ArrayData(authMethods, types.String),
		"anonymousSessionsEnabled":   llx.BoolDataPtr(anonymousSessionsActive(c.AnonymousSessions)),
		"myOrganization":             myOrg,
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// initAuth0Client resolves an application by its client ID on demand, for typed
// references (e.g. auth0.connection.enabledClients) and direct lookups.
func initAuth0Client(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// fast path: the caller already provided a fully populated resource
	if len(args) > 2 {
		return args, nil, nil
	}

	idArg, ok := args["id"]
	if !ok {
		return nil, nil, fmt.Errorf("auth0.client requires an id argument")
	}
	id, ok := idArg.Value.(string)
	if !ok || id == "" {
		return nil, nil, fmt.Errorf("auth0.client requires a valid id")
	}

	conn := runtime.Connection.(*connection.Auth0Connection)
	c, err := conn.Client().Client.Read(context.Background(), id)
	if err != nil {
		return nil, nil, fmt.Errorf("auth0.client with id %q not found: %w", id, err)
	}

	res, err := newMqlAuth0Client(runtime, c)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// enabledConnections resolves the identity connections this application is
// enabled on, as typed auth0.connection references.
func (c *mqlAuth0Client) enabledConnections() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.Auth0Connection)

	list, err := conn.Client().Client.ReadEnabledConnections(context.Background(), c.Id.Data)
	if err != nil {
		return nil, err
	}

	var result []any
	for _, ec := range list.Connections {
		if ec.ID == nil {
			continue
		}
		// Resolve by ID so initAuth0Connection fetches the fully-populated
		// connection instead of caching a partial one under the same __id.
		r, err := NewResource(c.MqlRuntime, "auth0.connection",
			map[string]*llx.RawData{"id": llx.StringData(*ec.ID)})
		if err != nil {
			log.Debug().Err(err).Str("connection", *ec.ID).Msg("auth0> unable to resolve enabled connection")
			continue
		}
		result = append(result, r)
	}
	return result, nil
}

func (r *mqlAuth0Client) id() (string, error) {
	return "auth0.client/" + r.Id.Data, nil
}

// anonymousSessionsActive returns whether the client may create anonymous
// sessions, or nil when the API did not report the setting.
func anonymousSessionsActive(a *management.ClientAnonymousSessions) *bool {
	if a == nil {
		return nil
	}
	return a.Active
}

// mqlAuth0ClientMyOrganizationConfigurationInternal caches the raw invitation
// landing client ID so the accessor can resolve it into an auth0.client.
type mqlAuth0ClientMyOrganizationConfigurationInternal struct {
	cacheInvitationLandingClientId *string
}

// myOrganizationArgs maps the SDK My Organization configuration to the MQL
// field values, preserving absent settings as null.
func myOrganizationArgs(cfg *management.MyOrganizationConfiguration) map[string]*llx.RawData {
	strategies := llx.NilData
	if cfg.AllowedStrategies != nil {
		strategies = llx.ArrayData(strList(cfg.AllowedStrategies), types.String)
	}
	return map[string]*llx.RawData{
		"enforcePermissionCeiling":         llx.BoolDataPtr(cfg.EnforcePermissionCeiling),
		"enforceSelfAssignmentRestriction": llx.BoolDataPtr(cfg.EnforceSelfAssignmentRestriction),
		"allowedStrategies":                strategies,
		"connectionDeletionBehavior":       llx.StringDataPtr(cfg.ConnectionDeletionBehavior),
	}
}

// newMqlAuth0ClientMyOrganization builds the My Organization sub-resource for a
// client, or a null value when the client has no such configuration.
func newMqlAuth0ClientMyOrganization(runtime *plugin.Runtime, clientID *string, cfg *management.MyOrganizationConfiguration) (*llx.RawData, error) {
	if cfg == nil || clientID == nil || *clientID == "" {
		return llx.NilData, nil
	}
	args := myOrganizationArgs(cfg)
	args["__id"] = llx.StringData("auth0.client/" + *clientID + "/myOrganization")
	r, err := CreateResource(runtime, "auth0.client.myOrganizationConfiguration", args)
	if err != nil {
		return nil, err
	}
	r.(*mqlAuth0ClientMyOrganizationConfiguration).cacheInvitationLandingClientId = cfg.InvitationLandingClientID
	return llx.ResourceData(r, "auth0.client.myOrganizationConfiguration"), nil
}

// invitationLandingClient resolves the application used as the invitation
// landing page into an auth0.client.
func (m *mqlAuth0ClientMyOrganizationConfiguration) invitationLandingClient() (*mqlAuth0Client, error) {
	if m.cacheInvitationLandingClientId == nil || *m.cacheInvitationLandingClientId == "" {
		m.InvitationLandingClient.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(m.MqlRuntime, "auth0.client",
		map[string]*llx.RawData{"id": llx.StringDataPtr(m.cacheInvitationLandingClientId)})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAuth0Client), nil
}
