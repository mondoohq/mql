// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"context"
	"fmt"
	"time"

	cloudflare "github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

type mqlCloudflareTunnelInternal struct {
	accountID string
}

// tunnelConfiguration is the tunnel-configuration response.
//
// cloudflare-go types every originRequest boolean as a plain bool, so a setting
// the configuration does not mention decodes as false — which would report
// "cloudflared validates the origin certificate" for an ingress rule that simply
// inherits the tunnel-wide default, and the opposite when that default is true.
// It also drops warp-routing entirely. Decoding the payload here with pointers
// keeps absent distinguishable from explicitly false and preserves the field.
type tunnelConfiguration struct {
	TunnelID string `json:"tunnel_id"`
	Version  int64  `json:"version"`
	Source   string `json:"source"`
	Config   *struct {
		Ingress       []tunnelIngressRule  `json:"ingress"`
		OriginRequest *tunnelOriginRequest `json:"originRequest"`
		WarpRouting   *struct {
			Enabled *bool `json:"enabled"`
		} `json:"warp-routing"`
	} `json:"config"`
}

type tunnelIngressRule struct {
	Hostname      string               `json:"hostname"`
	Path          string               `json:"path"`
	Service       string               `json:"service"`
	OriginRequest *tunnelOriginRequest `json:"originRequest"`
}

type tunnelOriginRequest struct {
	NoTLSVerify      *bool   `json:"noTLSVerify"`
	CAPool           *string `json:"caPool"`
	OriginServerName *string `json:"originServerName"`
	HTTPHostHeader   *string `json:"httpHostHeader"`
	HTTP2Origin      *bool   `json:"http2Origin"`
	ProxyType        *string `json:"proxyType"`
	Access           *struct {
		Required *bool `json:"required"`
	} `json:"access"`
}

// configuration reads the tunnel's ingress rules and origin connection settings.
//
// Only a remotely managed cloudflared tunnel has a configuration to read: a WARP
// connector has no ingress at all, and a locally managed cloudflared tunnel keeps
// its configuration in a YAML file on the connector host. Both report null rather
// than an empty configuration, which would read as a tunnel that publishes
// nothing.
func (c *mqlCloudflareTunnel) configuration() (*mqlCloudflareTunnelConfiguration, error) {
	if c.TunnelType.Data != "cfd_tunnel" || c.accountID == "" {
		c.Configuration.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var env struct {
		Result tunnelConfiguration `json:"result"`
	}
	uri := fmt.Sprintf("accounts/%s/cfd_tunnel/%s/configurations", c.accountID, c.Id.Data)
	if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
		if isUnavailable(err) {
			c.Configuration.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}
	cfg := env.Result

	// A locally managed tunnel answers with a null config: the ingress rules
	// exist only on the connector host.
	if cfg.Config == nil {
		c.Configuration.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	ingress, err := c.tunnelIngressResources(cfg.Config.Ingress)
	if err != nil {
		return nil, err
	}

	origin := cfg.Config.OriginRequest
	if origin == nil {
		origin = &tunnelOriginRequest{}
	}

	warpRouting := llx.NilData
	if cfg.Config.WarpRouting != nil {
		warpRouting = llx.BoolDataPtr(cfg.Config.WarpRouting.Enabled)
	}

	res, err := CreateResource(c.MqlRuntime, "cloudflare.tunnel.configuration", map[string]*llx.RawData{
		"__id":    llx.StringData("cloudflare.tunnel.configuration@" + c.accountID + "/" + c.Id.Data),
		"source":  llx.StringData(cfg.Source),
		"version": llx.IntData(cfg.Version),
		"ingress": llx.ArrayData(ingress, types.Resource("cloudflare.tunnel.ingressRule")),

		"originNoTlsVerify":  llx.BoolDataPtr(origin.NoTLSVerify),
		"originCaPool":       llx.StringDataPtr(origin.CAPool),
		"originServerName":   llx.StringDataPtr(origin.OriginServerName),
		"originHttp2":        llx.BoolDataPtr(origin.HTTP2Origin),
		"originProxyType":    llx.StringDataPtr(origin.ProxyType),
		"warpRoutingEnabled": warpRouting,
	})
	if err != nil {
		return nil, err
	}

	return res.(*mqlCloudflareTunnelConfiguration), nil
}

// tunnelIngressResources builds the ingress-rule resources for one tunnel. The
// list index is part of the cache key because ingress rules are ordered and two
// rules may share a hostname and path.
func (c *mqlCloudflareTunnel) tunnelIngressResources(rules []tunnelIngressRule) ([]any, error) {
	result := make([]any, 0, len(rules))
	for i := range rules {
		rule := rules[i]

		origin := rule.OriginRequest
		if origin == nil {
			origin = &tunnelOriginRequest{}
		}

		accessRequired := llx.NilData
		if origin.Access != nil {
			accessRequired = llx.BoolDataPtr(origin.Access.Required)
		}

		res, err := CreateResource(c.MqlRuntime, "cloudflare.tunnel.ingressRule", map[string]*llx.RawData{
			"__id": llx.StringData(fmt.Sprintf("cloudflare.tunnel.ingressRule@%s/%s/%d/%s%s",
				c.accountID, c.Id.Data, i, rule.Hostname, rule.Path)),
			"hostname": llx.StringData(rule.Hostname),
			"path":     llx.StringData(rule.Path),
			"service":  llx.StringData(rule.Service),

			"noTlsVerify":      llx.BoolDataPtr(origin.NoTLSVerify),
			"caPool":           llx.StringDataPtr(origin.CAPool),
			"originServerName": llx.StringDataPtr(origin.OriginServerName),
			"httpHostHeader":   llx.StringDataPtr(origin.HTTPHostHeader),
			"http2Origin":      llx.BoolDataPtr(origin.HTTP2Origin),
			"accessRequired":   accessRequired,
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

func (c *mqlCloudflareTunnel) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareTunnelConnection) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareAccount) tunnels() ([]any, error) {
	return fetchTunnels(c.MqlRuntime, c.Id.Data)
}

func fetchTunnels(runtime *plugin.Runtime, accountID string) ([]any, error) {
	conn := runtime.Connection.(*connection.CloudflareConnection)

	var result []any
	iter := conn.Cf.ZeroTrust.Tunnels.Cloudflared.ListAutoPaging(context.TODO(), zero_trust.TunnelCloudflaredListParams{
		AccountID: cloudflare.F(accountID),
	})
	for iter.Next() {
		rec := iter.Current()

		// The inline connections field on the list response is deprecated in
		// cloudflare-go in favor of the dedicated per-tunnel connections
		// endpoint, so fetch connection details from there instead.
		connections, err := tunnelConnections(runtime, conn, accountID, rec.ID, string(rec.TunType))
		if err != nil {
			return nil, err
		}

		tunnelRes, err := NewResource(runtime, "cloudflare.tunnel", map[string]*llx.RawData{
			"id":         llx.StringData(rec.ID),
			"name":       llx.StringData(rec.Name),
			"tunnelType": llx.StringData(string(rec.TunType)),
			"status":     llx.StringData(string(rec.Status)),
			// cloudflare-go deprecates the remote_config bool in favor of config_src;
			// "cloudflare" means the tunnel is managed remotely from the
			// Zero Trust dashboard, which is what remote_config==true meant.
			"remoteConfig": llx.BoolData(string(rec.ConfigSrc) == "cloudflare"),
			"createdAt":    timeOrNil(rec.CreatedAt),
			"deletedAt":    timeOrNil(rec.DeletedAt),
			"connections":  llx.ArrayData(connections, "cloudflare.tunnel.connection"),
		})
		if err != nil {
			return nil, err
		}
		tunnelRes.(*mqlCloudflareTunnel).accountID = accountID

		result = append(result, tunnelRes)
	}
	if err := iter.Err(); err != nil {
		return degradedList(err)
	}

	return result, nil
}

// tunnelConnections fetches the active connections for a single tunnel from the
// dedicated connections endpoint. This endpoint only serves cloudflared
// ("cfd_tunnel") tunnels; other tunnel types (e.g. warp_connector) have no
// connections here, so we return an empty list for them.
func tunnelConnections(runtime *plugin.Runtime, conn *connection.CloudflareConnection, accountID, tunnelID, tunType string) ([]any, error) {
	connections := []any{}
	if tunType != "cfd_tunnel" {
		return connections, nil
	}

	iter := conn.Cf.ZeroTrust.Tunnels.Cloudflared.Connections.GetAutoPaging(context.TODO(), tunnelID, zero_trust.TunnelCloudflaredConnectionGetParams{
		AccountID: cloudflare.F(accountID),
	})
	for iter.Next() {
		client := iter.Current()
		for j := range client.Conns {
			tc := client.Conns[j]

			connRes, err := NewResource(runtime, "cloudflare.tunnel.connection", map[string]*llx.RawData{
				"__id":          llx.StringData(fmt.Sprintf("tunnelConn@%s@%s", tunnelID, tc.ID)),
				"id":            llx.StringData(tc.ID),
				"coloName":      llx.StringData(tc.ColoName),
				"clientId":      llx.StringData(tc.ClientID),
				"clientVersion": llx.StringData(tc.ClientVersion),
				"openedAt":      timeOrNil(tc.OpenedAt),
				"originIp":      llx.StringData(tc.OriginIP),
				// Cloudflare dropped is_pending_reconnect from the tunnel
				// connections API, so there is nothing to read. Report null
				// rather than false, which would claim the connection is
				// actively serving traffic.
				"isPendingReconnect": llx.NilData,
			})
			if err != nil {
				return nil, err
			}
			connections = append(connections, connRes)
		}
	}
	if err := iter.Err(); err != nil {
		return degradedList(err)
	}

	return connections, nil
}

type mqlCloudflareTunnelRouteInternal struct {
	cacheVirtualNetworkID string
}

func (c *mqlCloudflareTunnelRoute) virtualNetwork() (*mqlCloudflareTunnelVirtualNetwork, error) {
	if c.cacheVirtualNetworkID == "" {
		c.VirtualNetwork.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(c.MqlRuntime, "cloudflare.tunnel.virtualNetwork", map[string]*llx.RawData{
		"id": llx.StringData(c.cacheVirtualNetworkID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlCloudflareTunnelVirtualNetwork), nil
}

func (c *mqlCloudflareTunnelRoute) id() (string, error) {
	if c.Network.Error != nil {
		return "", c.Network.Error
	}
	if c.TunnelId.Error != nil {
		return "", c.TunnelId.Error
	}
	return tunnelRouteID(c.Network.Data, c.TunnelId.Data, c.cacheVirtualNetworkID), nil
}

func tunnelRouteID(network, tunnelID, vnetID string) string {
	return fmt.Sprintf("tunnelRoute@%s@%s@%s", network, tunnelID, vnetID)
}

// tunnelRoute mirrors a Cloudflare Tunnel (teamnet) route. The endpoint is
// page-numbered without a total_pages count, so we decode it via the client's
// generic Get and stop on the first short page.
type tunnelRouteRecord struct {
	Network          string    `json:"network"`
	TunnelID         string    `json:"tunnel_id"`
	TunnelName       string    `json:"tunnel_name"`
	Comment          string    `json:"comment"`
	VirtualNetworkID string    `json:"virtual_network_id"`
	CreatedAt        time.Time `json:"created_at"`
	DeletedAt        time.Time `json:"deleted_at"`
}

func (c *mqlCloudflareAccount) tunnelRoutes() ([]any, error) {
	return fetchTunnelRoutes(c.MqlRuntime, c.Id.Data)
}

func fetchTunnelRoutes(runtime *plugin.Runtime, accountID string) ([]any, error) {
	conn := runtime.Connection.(*connection.CloudflareConnection)

	const perPage = 50
	var result []any
	page := 1
	for {
		var env struct {
			Result []tunnelRouteRecord `json:"result"`
		}
		uri := fmt.Sprintf("accounts/%s/teamnet/routes?per_page=%d&page=%d", accountID, perPage, page)
		if err := conn.Cf.Get(context.TODO(), uri, nil, &env); err != nil {
			return degradedList(err)
		}

		for i := range env.Result {
			rec := env.Result[i]

			res, err := CreateResource(runtime, "cloudflare.tunnel.route", map[string]*llx.RawData{
				"__id":       llx.StringData(tunnelRouteID(rec.Network, rec.TunnelID, rec.VirtualNetworkID)),
				"network":    llx.StringData(rec.Network),
				"tunnelId":   llx.StringData(rec.TunnelID),
				"tunnelName": llx.StringData(rec.TunnelName),
				"comment":    llx.StringData(rec.Comment),
				"createdAt":  timeOrNil(rec.CreatedAt),
				"deletedAt":  timeOrNil(rec.DeletedAt),
			})
			if err != nil {
				return nil, err
			}

			res.(*mqlCloudflareTunnelRoute).cacheVirtualNetworkID = rec.VirtualNetworkID
			result = append(result, res)
		}

		if len(env.Result) < perPage {
			break
		}
		page++
	}

	return result, nil
}

func (c *mqlCloudflareTunnelVirtualNetwork) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return c.Id.Data, nil
}

func (c *mqlCloudflareAccount) tunnelVirtualNetworks() ([]any, error) {
	return fetchTunnelVirtualNetworks(c.MqlRuntime, c.Id.Data)
}

func fetchTunnelVirtualNetworks(runtime *plugin.Runtime, accountID string) ([]any, error) {
	conn := runtime.Connection.(*connection.CloudflareConnection)

	var result []any
	iter := conn.Cf.ZeroTrust.Networks.VirtualNetworks.ListAutoPaging(context.TODO(), zero_trust.NetworkVirtualNetworkListParams{
		AccountID: cloudflare.F(accountID),
	})
	for iter.Next() {
		rec := iter.Current()

		res, err := NewResource(runtime, "cloudflare.tunnel.virtualNetwork", map[string]*llx.RawData{
			"id":               llx.StringData(rec.ID),
			"name":             llx.StringData(rec.Name),
			"comment":          llx.StringData(rec.Comment),
			"isDefaultNetwork": llx.BoolData(rec.IsDefaultNetwork),
			"createdAt":        timeOrNil(rec.CreatedAt),
			"deletedAt":        timeOrNil(rec.DeletedAt),
		})
		if err != nil {
			return nil, err
		}

		result = append(result, res)
	}
	if err := iter.Err(); err != nil {
		return degradedList(err)
	}

	return result, nil
}
