// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"
	"strings"

	"github.com/digitalocean/godo"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/digitalocean/connection"
	"go.mondoo.com/mql/types"
)

// actionGatewayPageSize is the page size requested from the Action Gateway
// connection list.
const actionGatewayPageSize = 100

// ----- connections -----

// listActionGatewayConnections walks the page/per_page pagination of the
// connection list.
func listActionGatewayConnections(ctx context.Context, svc *godo.ActionGatewayConnectionsService) ([]godo.ActionGatewayConnection, error) {
	return paginateOffset(ctx, actionGatewayPageSize,
		func(c godo.ActionGatewayConnection) string { return c.ID },
		func(ctx context.Context, page int) ([]godo.ActionGatewayConnection, int, error) {
			resp, _, err := svc.List(ctx, &godo.ActionGatewayConnectionListOptions{Page: page, PerPage: actionGatewayPageSize})
			if err != nil {
				return nil, 0, err
			}
			if resp == nil {
				return nil, -1, nil
			}
			total := -1
			if resp.Pagination != nil {
				total = resp.Pagination.Total
			}
			return resp.Connections, total, nil
		})
}

// actionGatewayConnectionVPC returns the VPC block of a connection, or nil.
func actionGatewayConnectionVPC(c *godo.ActionGatewayConnection) *godo.ActionGatewayConnectionVPC {
	if c.Network == nil {
		return nil
	}
	return c.Network.VPC
}

// actionGatewayDestinations converts a connection's VPC destinations to
// dicts.
func actionGatewayDestinations(vpc *godo.ActionGatewayConnectionVPC) []any {
	out := []any{}
	if vpc == nil {
		return out
	}
	for _, d := range vpc.Destinations {
		out = append(out, map[string]any{
			"host":           d.Host,
			"port":           int64(d.Port),
			"allowedIpCidrs": toAnySlice(d.AllowedIPCIDRs),
		})
	}
	return out
}

// actionGatewayConnectionArgs maps a connection to its MQL fields. The API key
// block, the connection parameters (free-form provider settings that may hold
// credentials), and any authorization handle are left out.
//
// The grant is reported at the top level of the connection; older responses
// carry it only in the oauth block, which is the fallback.
func actionGatewayConnectionArgs(c *godo.ActionGatewayConnection) (map[string]*llx.RawData, error) {
	id, err := resourceID("digitalocean.actionGatewayConnection", c.ID)
	if err != nil {
		return nil, err
	}
	scopes := c.Scopes
	grantedAt := c.GrantedAt
	if c.OAuth != nil {
		if len(scopes) == 0 {
			scopes = c.OAuth.Scopes
		}
		if grantedAt == nil {
			grantedAt = c.OAuth.GrantedAt
		}
	}
	return map[string]*llx.RawData{
		"__id":                llx.StringData(id),
		"id":                  llx.StringData(c.ID),
		"provider":            llx.StringData(c.Provider),
		"providerDisplayName": llx.StringData(c.ProviderDisplayName),
		"userId":              llx.StringData(c.UserID),
		"status":              llx.StringData(c.Status),
		"credentialKind":      llx.StringData(c.CredentialKind),
		"scopes":              llx.ArrayData(toAnySlice(scopes), types.String),
		"grantedAt":           llx.TimeDataPtr(gradientaiTime(grantedAt)),
		"revokedAt":           llx.TimeDataPtr(gradientaiTime(c.RevokedAt)),
		"owningUserUuid":      llx.StringData(c.OwningUserID),
		"vpcDestinations":     llx.ArrayData(actionGatewayDestinations(actionGatewayConnectionVPC(c)), types.Dict),
		"createdAt":           llx.TimeDataPtr(gradientaiTime(c.CreatedAt)),
		"updatedAt":           llx.TimeDataPtr(gradientaiTime(c.UpdatedAt)),
	}, nil
}

// mqlDigitaloceanActionGatewayConnectionInternal keeps the ids the typed
// accessors resolve from the account's listings.
type mqlDigitaloceanActionGatewayConnectionInternal struct {
	cacheCredentialID string
	cacheVpcID        string
}

func (r *mqlDigitalocean) actionGatewayConnections() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	conns, err := listActionGatewayConnections(context.Background(), conn.Client().ActionGateway.Connections)
	if err != nil {
		return nil, classifyDoError(err)
	}
	out := make([]any, 0, len(conns))
	for i := range conns {
		c := &conns[i]
		args, err := actionGatewayConnectionArgs(c)
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.actionGatewayConnection", args)
		if err != nil {
			return nil, err
		}
		mc := res.(*mqlDigitaloceanActionGatewayConnection)
		mc.cacheCredentialID = c.CredentialID
		if vpc := actionGatewayConnectionVPC(c); vpc != nil {
			mc.cacheVpcID = vpc.VPCUUID
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDigitaloceanActionGatewayConnection) id() (string, error) {
	return resourceID("digitalocean.actionGatewayConnection", r.Id.Data)
}

func (r *mqlDigitaloceanActionGatewayConnection) vpc() (*mqlDigitaloceanVpc, error) {
	return resolveVpcRef(r.MqlRuntime, &r.Vpc, r.cacheVpcID)
}

func (r *mqlDigitaloceanActionGatewayConnection) providerCredential() (*mqlDigitaloceanActionGatewayProviderCredential, error) {
	if strings.TrimSpace(r.cacheCredentialID) == "" {
		r.ProviderCredential.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	parent, err := parentDigitalocean(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	cred, err := parent.actionGatewayCredentialByID(r.cacheCredentialID)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		r.ProviderCredential.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return cred, nil
}

// ----- provider credentials -----

// actionGatewayProviderCredentialArgs maps a provider credential to its MQL
// fields. The API returns no key, client ID, or client secret; the redirect
// and discovery authorization URLs are left out, and any password embedded
// in the base URL is removed.
func actionGatewayProviderCredentialArgs(c *godo.ActionGatewayProviderCredential) (map[string]*llx.RawData, error) {
	id, err := resourceID("digitalocean.actionGatewayProviderCredential", c.ID)
	if err != nil {
		return nil, err
	}
	discoveryStatus := ""
	discoveryConsentedAt := llx.NilData
	if c.Discovery != nil {
		discoveryStatus = c.Discovery.Status
		discoveryConsentedAt = llx.TimeDataPtr(gradientaiTime(c.Discovery.ConsentedAt))
	}
	return map[string]*llx.RawData{
		"__id":                 llx.StringData(id),
		"id":                   llx.StringData(c.ID),
		"provider":             llx.StringData(c.Provider),
		"displayName":          llx.StringData(c.DisplayName),
		"kind":                 llx.StringData(c.Kind),
		"status":               llx.StringData(c.Status),
		"reusableByTeam":       llx.BoolData(c.ReusableByTeam),
		"scope":                llx.StringData(c.Scope),
		"baseUrl":              llx.StringData(redactURLPassword(c.BaseURL)),
		"owningUserUuid":       llx.StringData(c.OwningUserID),
		"discoveryStatus":      llx.StringData(discoveryStatus),
		"discoveryConsentedAt": discoveryConsentedAt,
		"createdAt":            llx.TimeDataPtr(gradientaiTime(c.CreatedAt)),
		"updatedAt":            llx.TimeDataPtr(gradientaiTime(c.UpdatedAt)),
	}, nil
}

func (r *mqlDigitalocean) actionGatewayProviderCredentials() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	// The credential list is not paginated.
	resp, _, err := conn.Client().ActionGateway.ProviderCredentials.List(context.Background(), nil)
	if err != nil {
		return nil, classifyDoError(err)
	}
	out := []any{}
	if resp == nil {
		return out, nil
	}
	for i := range resp.Credentials {
		args, err := actionGatewayProviderCredentialArgs(&resp.Credentials[i])
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.actionGatewayProviderCredential", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDigitaloceanActionGatewayProviderCredential) id() (string, error) {
	return resourceID("digitalocean.actionGatewayProviderCredential", r.Id.Data)
}

// actionGatewayCredentialByID resolves a provider credential from the
// account's credential listing, read once per scan.
func (r *mqlDigitalocean) actionGatewayCredentialByID(id string) (*mqlDigitaloceanActionGatewayProviderCredential, error) {
	r.actionGatewayCredentialIndexOnce.Do(func() {
		creds := r.GetActionGatewayProviderCredentials()
		if creds.Error != nil {
			r.actionGatewayCredentialIndexErr = creds.Error
			return
		}
		idx := make(map[string]*mqlDigitaloceanActionGatewayProviderCredential, len(creds.Data))
		for _, c := range creds.Data {
			mc := c.(*mqlDigitaloceanActionGatewayProviderCredential)
			idx[mc.Id.Data] = mc
		}
		r.actionGatewayCredentialIndex = idx
	})
	if r.actionGatewayCredentialIndexErr != nil {
		return nil, r.actionGatewayCredentialIndexErr
	}
	return r.actionGatewayCredentialIndex[id], nil
}

// ----- MCP servers -----

// actionGatewayMcpServerArgs maps a registered MCP server to its MQL fields.
// The credential reference and the OAuth authorize URL are left out, and any
// password embedded in the endpoint is removed.
func actionGatewayMcpServerArgs(s *godo.ActionGatewayMCPServer) (map[string]*llx.RawData, error) {
	id, err := resourceID("digitalocean.actionGatewayMcpServer", s.ServerRef)
	if err != nil {
		return nil, err
	}
	// The lifetime arrives as a decimal string (proto JSON int64). An empty or
	// unparseable value stays null rather than reading as zero seconds.
	ttl := llx.NilData
	if v, err := strconv.ParseInt(strings.TrimSpace(s.OAuthAuthorizationTTLSeconds), 10, 64); err == nil {
		ttl = llx.IntData(v)
	}
	return map[string]*llx.RawData{
		"__id":                         llx.StringData(id),
		"name":                         llx.StringData(s.ServerRef),
		"description":                  llx.StringData(s.Description),
		"endpoint":                     llx.StringData(redactURLPassword(s.Endpoint)),
		"transport":                    llx.StringData(s.Transport),
		"credentialRefSource":          llx.StringData(s.CredentialRefSource),
		"oauthScopes":                  llx.ArrayData(toAnySlice(s.OAuthScopes), types.String),
		"oauthAuthorizationTtlSeconds": ttl,
		"syncStatus":                   llx.StringData(s.SyncStatus),
		"syncError":                    llx.StringData(s.SyncError),
		"lastSyncedAt":                 llx.TimeDataPtr(parseDoTime(s.LastSyncedAt)),
		"protocolVersion":              llx.StringData(s.ProtocolVersion),
		"toolCount":                    llx.IntData(int64(s.ToolCount)),
		"createdAt":                    llx.TimeDataPtr(parseDoTime(s.CreatedAt)),
		"updatedAt":                    llx.TimeDataPtr(parseDoTime(s.UpdatedAt)),
	}, nil
}

func (r *mqlDigitalocean) actionGatewayMcpServers() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DigitaloceanConnection)
	// The server list is not paginated.
	resp, _, err := conn.Client().ActionGateway.MCPServers.List(context.Background())
	if err != nil {
		return nil, classifyDoError(err)
	}
	out := []any{}
	if resp == nil {
		return out, nil
	}
	for i := range resp.MCPServers {
		args, err := actionGatewayMcpServerArgs(&resp.MCPServers[i])
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(r.MqlRuntime, "digitalocean.actionGatewayMcpServer", args)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlDigitaloceanActionGatewayMcpServer) id() (string, error) {
	return resourceID("digitalocean.actionGatewayMcpServer", r.Name.Data)
}
