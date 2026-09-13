// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/alibabacloud-go/tea/tea"
	vpcclient "github.com/alibabacloud-go/vpc-20160428/v7/client"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/alicloud/connection"
	"go.mondoo.com/mql/v13/types"
)

// vpnPageSize is the per-request item count for the page-numbered VPN APIs.
const vpnPageSize int32 = 50

// vpnCapabilityEnabled maps the enable/disable strings the VPN gateway API uses
// for its IPsec and SSL capabilities to a bool, returning nil for an absent or
// unrecognized value so the field reads as null rather than claiming the
// capability is off.
func vpnCapabilityEnabled(v *string) *bool {
	if v == nil {
		return nil
	}
	switch *v {
	case "enable":
		enabled := true
		return &enabled
	case "disable":
		disabled := false
		return &disabled
	default:
		return nil
	}
}

// vpnGatewayTags flattens a gateway's tag list, so a caller can apply the tag
// filters before paying to build the resource.
func vpnGatewayTags(g *vpcclient.DescribeVpnGatewaysResponseBodyVpnGatewaysVpnGateway) map[string]any {
	tags := map[string]any{}
	if g.Tags == nil {
		return tags
	}
	for _, t := range g.Tags.Tag {
		if t == nil || t.Key == nil {
			continue
		}
		tags[tea.StringValue(t.Key)] = tea.StringValue(t.Value)
	}
	return tags
}

// ---------------------------------------------------------------------------
// alicloud.vpc.vpnGateway
// ---------------------------------------------------------------------------

func (r *mqlAlicloudVpcVpnGateway) id() (string, error) {
	return r.RegionId.Data + "/" + r.VpnGatewayId.Data, nil
}

// mqlAlicloudVpcVpnGatewayInternal caches the identifiers the gateway's typed
// VPC and vSwitch references need.
type mqlAlicloudVpcVpnGatewayInternal struct {
	cacheRegion    string
	cacheVpcID     string
	cacheVswitchID string
}

func (r *mqlAlicloudVpc) vpnGateways() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		gateways, err := vpnGatewaysInRegion(r.MqlRuntime, conn, region, "")
		if err != nil {
			// a region may be un-activated or access-denied; skip it rather
			// than failing the whole scan, but leave a trace so a region
			// missing from the results can be explained
			log.Debug().Err(err).Str("region", region).
				Msg("alicloud: could not list VPN gateways in region")
			continue
		}
		res = append(res, gateways...)
	}
	return res, nil
}

// vpnGateways lists the gateways attached to this VPC.
func (r *mqlAlicloudVpcNetwork) vpnGateways() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	return vpnGatewaysInRegion(r.MqlRuntime, conn, r.RegionId.Data, r.VpcId.Data)
}

// vpnGatewaysInRegion lists the VPN gateways in one region, narrowed to a
// single VPC when vpcID is set.
func vpnGatewaysInRegion(runtime *plugin.Runtime, conn *connection.AlicloudConnection, region, vpcID string) ([]any, error) {
	client, err := conn.VpcClient(region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int32(1)
	for {
		req := &vpcclient.DescribeVpnGatewaysRequest{
			RegionId:   tea.String(region),
			PageNumber: tea.Int32(pageNumber),
			PageSize:   tea.Int32(vpnPageSize),
		}
		if vpcID != "" {
			req.VpcId = tea.String(vpcID)
		}
		resp, err := client.DescribeVpnGateways(req)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.VpnGateways == nil {
			break
		}

		items := resp.Body.VpnGateways.VpnGateway
		for _, g := range items {
			if g == nil || g.VpnGatewayId == nil {
				continue
			}
			// check the tag filters before building the resource, so a
			// filtered-out gateway is never cached
			tags := vpnGatewayTags(g)
			if filteredOutByTags(conn, tags) {
				continue
			}
			gateway, err := newVpnGateway(runtime, region, g, tags)
			if err != nil {
				return nil, err
			}
			res = append(res, gateway)
		}

		total := tea.Int32Value(resp.Body.TotalCount)
		if len(items) == 0 || total == 0 || pageNumber*vpnPageSize >= total {
			break
		}
		pageNumber++
	}
	return res, nil
}

func newVpnGateway(runtime *plugin.Runtime, region string, g *vpcclient.DescribeVpnGatewaysResponseBodyVpnGatewaysVpnGateway, tags map[string]any) (*mqlAlicloudVpcVpnGateway, error) {
	resource, err := CreateResource(runtime, "alicloud.vpc.vpnGateway", map[string]*llx.RawData{
		"__id":              llx.StringData(region + "/" + tea.StringValue(g.VpnGatewayId)),
		"vpnGatewayId":      llx.StringDataPtr(g.VpnGatewayId),
		"name":              llx.StringDataPtr(g.Name),
		"description":       llx.StringDataPtr(g.Description),
		"regionId":          llx.StringData(region),
		"status":            llx.StringDataPtr(g.Status),
		"businessStatus":    llx.StringDataPtr(g.BusinessStatus),
		"internetIp":        llx.StringDataPtr(g.InternetIp),
		"ipsecVpnEnabled":   llx.BoolDataPtr(vpnCapabilityEnabled(g.IpsecVpn)),
		"sslVpnEnabled":     llx.BoolDataPtr(vpnCapabilityEnabled(g.SslVpn)),
		"sslMaxConnections": llx.IntDataPtr(g.SslMaxConnections),
		"sslVpnInternetIp":  llx.StringDataPtr(g.SslVpnInternetIp),
		"vpnType":           llx.StringDataPtr(g.VpnType),
		"networkType":       llx.StringDataPtr(g.NetworkType),
		"enableBgp":         llx.BoolDataPtr(g.EnableBgp),
		"autoPropagate":     llx.BoolDataPtr(g.AutoPropagate),
		"spec":              llx.StringDataPtr(g.Spec),
		"chargeType":        llx.StringDataPtr(g.ChargeType),
		"createTime":        llx.TimeDataPtr(configEpochMillis(g.CreateTime)),
		"endTime":           llx.TimeDataPtr(configEpochMillis(g.EndTime)),
		"resourceGroupId":   llx.StringDataPtr(g.ResourceGroupId),
		"tags":              llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}

	mqlGateway := resource.(*mqlAlicloudVpcVpnGateway)
	mqlGateway.cacheRegion = region
	mqlGateway.cacheVpcID = tea.StringValue(g.VpcId)
	mqlGateway.cacheVswitchID = tea.StringValue(g.VSwitchId)
	return mqlGateway, nil
}

func (r *mqlAlicloudVpcVpnGateway) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcID == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.cacheRegion, r.cacheVpcID)
}

func (r *mqlAlicloudVpcVpnGateway) vswitch() (*mqlAlicloudVpcVswitch, error) {
	if r.cacheVswitchID == "" {
		r.Vswitch.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcVswitch(r.MqlRuntime, r.cacheRegion, r.cacheVswitchID)
}

// connections lists the connections terminating on this gateway.
func (r *mqlAlicloudVpcVpnGateway) connections() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	return vpnConnectionsInRegion(r.MqlRuntime, conn, r.RegionId.Data, r.VpnGatewayId.Data)
}

// ---------------------------------------------------------------------------
// alicloud.vpc.vpnConnection
// ---------------------------------------------------------------------------

func (r *mqlAlicloudVpcVpnConnection) id() (string, error) {
	return r.RegionId.Data + "/" + r.VpnConnectionId.Data, nil
}

func (r *mqlAlicloudVpc) vpnConnections() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		connections, err := vpnConnectionsInRegion(r.MqlRuntime, conn, region, "")
		if err != nil {
			// a region may be un-activated or access-denied; skip it rather
			// than failing the whole scan, but leave a trace so a region
			// missing from the results can be explained
			log.Debug().Err(err).Str("region", region).
				Msg("alicloud: could not list VPN connections in region")
			continue
		}
		res = append(res, connections...)
	}
	return res, nil
}

// vpnConnectionsInRegion lists the VPN connections in one region, narrowed to a
// single gateway when gatewayID is set.
func vpnConnectionsInRegion(runtime *plugin.Runtime, conn *connection.AlicloudConnection, region, gatewayID string) ([]any, error) {
	client, err := conn.VpcClient(region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int32(1)
	for {
		req := &vpcclient.DescribeVpnConnectionsRequest{
			RegionId:   tea.String(region),
			PageNumber: tea.Int32(pageNumber),
			PageSize:   tea.Int32(vpnPageSize),
		}
		if gatewayID != "" {
			req.VpnGatewayId = tea.String(gatewayID)
		}
		resp, err := client.DescribeVpnConnections(req)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.VpnConnections == nil {
			break
		}

		items := resp.Body.VpnConnections.VpnConnection
		for _, c := range items {
			if c == nil || c.VpnConnectionId == nil {
				continue
			}
			vpnConn, err := newVpnConnection(runtime, region, c)
			if err != nil {
				return nil, err
			}
			res = append(res, vpnConn)
		}

		total := tea.Int32Value(resp.Body.TotalCount)
		if len(items) == 0 || total == 0 || pageNumber*vpnPageSize >= total {
			break
		}
		pageNumber++
	}
	return res, nil
}

// mqlAlicloudVpcVpnConnectionInternal caches what the typed gateway reference
// needs.
type mqlAlicloudVpcVpnConnectionInternal struct {
	cacheRegion  string
	cacheGateway string
}

func newVpnConnection(runtime *plugin.Runtime, region string, c *vpcclient.DescribeVpnConnectionsResponseBodyVpnConnectionsVpnConnection) (*mqlAlicloudVpcVpnConnection, error) {
	// The IKE configuration also carries the tunnel's pre-shared key. Only the
	// negotiated algorithms and lifetimes are mapped, so the secret never
	// reaches a scan result.
	var ikeVersion, ikeMode, ikeEncAlg, ikeAuthAlg, ikePfs *string
	var ikeLifetime *int64
	if c.IkeConfig != nil {
		ikeVersion = c.IkeConfig.IkeVersion
		ikeMode = c.IkeConfig.IkeMode
		ikeEncAlg = c.IkeConfig.IkeEncAlg
		ikeAuthAlg = c.IkeConfig.IkeAuthAlg
		ikePfs = c.IkeConfig.IkePfs
		ikeLifetime = c.IkeConfig.IkeLifetime
	}

	var ipsecEncAlg, ipsecAuthAlg, ipsecPfs *string
	var ipsecLifetime *int64
	if c.IpsecConfig != nil {
		ipsecEncAlg = c.IpsecConfig.IpsecEncAlg
		ipsecAuthAlg = c.IpsecConfig.IpsecAuthAlg
		ipsecPfs = c.IpsecConfig.IpsecPfs
		ipsecLifetime = c.IpsecConfig.IpsecLifetime
	}

	// The per-tunnel options ride along in this same response. A dual-tunnel
	// connection negotiates IKE and IPsec once per tunnel, which the
	// connection-level IkeConfig and IpsecConfig above cannot express.
	connectionKey := region + "/" + tea.StringValue(c.VpnConnectionId)
	tunnels, err := newVpnConnectionTunnels(runtime, connectionKey, c.TunnelOptionsSpecification)
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(runtime, "alicloud.vpc.vpnConnection", map[string]*llx.RawData{
		"__id":                         llx.StringData(connectionKey),
		"vpnConnectionId":              llx.StringDataPtr(c.VpnConnectionId),
		"name":                         llx.StringDataPtr(c.Name),
		"regionId":                     llx.StringData(region),
		"customerGatewayId":            llx.StringDataPtr(c.CustomerGatewayId),
		"status":                       llx.StringDataPtr(c.Status),
		"state":                        llx.StringDataPtr(c.State),
		"localSubnet":                  llx.StringDataPtr(c.LocalSubnet),
		"remoteSubnet":                 llx.StringDataPtr(c.RemoteSubnet),
		"internetIp":                   llx.StringDataPtr(c.InternetIp),
		"effectImmediately":            llx.BoolDataPtr(c.EffectImmediately),
		"enableDpd":                    llx.BoolDataPtr(c.EnableDpd),
		"enableNatTraversal":           llx.BoolDataPtr(c.EnableNatTraversal),
		"enableTunnelsBgp":             llx.BoolDataPtr(c.EnableTunnelsBgp),
		"crossAccountAuthorized":       llx.BoolDataPtr(c.CrossAccountAuthorized),
		"attachType":                   llx.StringDataPtr(c.AttachType),
		"attachInstanceId":             llx.StringDataPtr(c.AttachInstanceId),
		"ikeVersion":                   llx.StringDataPtr(ikeVersion),
		"ikeMode":                      llx.StringDataPtr(ikeMode),
		"ikeEncryptionAlgorithm":       llx.StringDataPtr(ikeEncAlg),
		"ikeAuthenticationAlgorithm":   llx.StringDataPtr(ikeAuthAlg),
		"ikePfs":                       llx.StringDataPtr(ikePfs),
		"ikeLifetime":                  llx.IntDataPtr(ikeLifetime),
		"ipsecEncryptionAlgorithm":     llx.StringDataPtr(ipsecEncAlg),
		"ipsecAuthenticationAlgorithm": llx.StringDataPtr(ipsecAuthAlg),
		"ipsecPfs":                     llx.StringDataPtr(ipsecPfs),
		"ipsecLifetime":                llx.IntDataPtr(ipsecLifetime),
		"createTime":                   llx.TimeDataPtr(configEpochMillis(c.CreateTime)),
		"tunnels":                      llx.ArrayData(tunnels, types.Resource("alicloud.vpc.vpnConnection.tunnel")),
	})
	if err != nil {
		return nil, err
	}

	mqlConn := resource.(*mqlAlicloudVpcVpnConnection)
	mqlConn.cacheRegion = region
	mqlConn.cacheGateway = tea.StringValue(c.VpnGatewayId)
	return mqlConn, nil
}

// vpnGateway resolves the gateway the connection terminates on.
func (r *mqlAlicloudVpcVpnConnection) vpnGateway() (*mqlAlicloudVpcVpnGateway, error) {
	if r.cacheGateway == "" || r.cacheRegion == "" {
		r.VpnGateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// a connection attached to a transit router rather than a VPN gateway
	// carries no gateway to resolve
	if x, ok := r.MqlRuntime.Resources.Get("alicloud.vpc.vpnGateway\x00" + r.cacheRegion + "/" + r.cacheGateway); ok {
		return x.(*mqlAlicloudVpcVpnGateway), nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.VpcClient(r.cacheRegion)
	if err != nil {
		return nil, err
	}
	resp, err := client.DescribeVpnGateways(&vpcclient.DescribeVpnGatewaysRequest{
		RegionId:     tea.String(r.cacheRegion),
		VpnGatewayId: tea.String(r.cacheGateway),
	})
	// A failed call is not the same as a gateway that is gone. Reporting a rate
	// limit or a timeout as a null gateway would hide the edge this resource
	// exists to expose, so only an empty answer resolves to null.
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Body == nil || resp.Body.VpnGateways == nil {
		log.Debug().Str("gateway", r.cacheGateway).
			Msg("alicloud: no VPN gateway returned for the connection's gateway id")
		r.VpnGateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	for _, g := range resp.Body.VpnGateways.VpnGateway {
		if g == nil || tea.StringValue(g.VpnGatewayId) != r.cacheGateway {
			continue
		}
		return newVpnGateway(r.MqlRuntime, r.cacheRegion, g, vpnGatewayTags(g))
	}

	r.VpnGateway.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
