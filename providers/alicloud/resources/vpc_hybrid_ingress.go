// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	tea "github.com/alibabacloud-go/tea/tea"
	vpcclient "github.com/alibabacloud-go/vpc-20160428/v7/client"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// vpcHybridPageSize is the page size used for the SSL VPN, customer gateway and
// Express Connect listings.
const vpcHybridPageSize = 50

// ---------------------------------------------------------------------------
// SSL VPN
// ---------------------------------------------------------------------------

// mqlAlicloudVpcSslVpnServerInternal caches the region and gateway the server
// was listed from, which its client-certificate listing and typed gateway
// reference need.
type mqlAlicloudVpcSslVpnServerInternal struct {
	region       string
	vpnGatewayID string
}

func (r *mqlAlicloudVpcSslVpnServer) id() (string, error) {
	return r.SslVpnServerId.Data, nil
}

func (r *mqlAlicloudVpcSslVpnClientCert) id() (string, error) {
	return r.SslVpnClientCertId.Data, nil
}

func (r *mqlAlicloudVpcSslVpnServer) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

func (r *mqlAlicloudVpcSslVpnClientCert) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

// sslVpnServers enumerates the account's SSL VPN servers across every scanned
// region. A region that is not activated, or that the credentials may not read,
// is skipped rather than failing the whole listing.
func (r *mqlAlicloudVpc) sslVpnServers() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.VpcClient(region)
		if err != nil {
			return nil, err
		}

		pageNumber := int32(1)
		collected := int32(0)
		for {
			resp, err := client.DescribeSslVpnServers(&vpcclient.DescribeSslVpnServersRequest{
				RegionId:   tea.String(region),
				PageNumber: tea.Int32(pageNumber),
				PageSize:   tea.Int32(vpcHybridPageSize),
			})
			if err != nil {
				log.Debug().Err(err).Str("region", region).
					Msg("alicloud> could not list SSL VPN servers")
				break
			}
			if resp == nil || resp.Body == nil || resp.Body.SslVpnServers == nil {
				break
			}
			items := resp.Body.SslVpnServers.SslVpnServer
			for _, srv := range items {
				if srv == nil || srv.SslVpnServerId == nil {
					continue
				}
				resource, err := CreateResource(r.MqlRuntime, "alicloud.vpc.sslVpnServer", map[string]*llx.RawData{
					"__id":                   llx.StringDataPtr(srv.SslVpnServerId),
					"regionId":               llx.StringData(region),
					"sslVpnServerId":         llx.StringDataPtr(srv.SslVpnServerId),
					"name":                   llx.StringDataPtr(srv.Name),
					"vpnGatewayId":           llx.StringDataPtr(srv.VpnGatewayId),
					"internetIp":             llx.StringDataPtr(srv.InternetIp),
					"clientIpPool":           llx.StringDataPtr(srv.ClientIpPool),
					"localSubnet":            llx.StringDataPtr(srv.LocalSubnet),
					"port":                   llx.IntData(int64(tea.Int32Value(srv.Port))),
					"proto":                  llx.StringDataPtr(srv.Proto),
					"cipher":                 llx.StringDataPtr(srv.Cipher),
					"compress":               llx.BoolData(tea.BoolValue(srv.Compress)),
					"connections":            llx.IntData(int64(tea.Int32Value(srv.Connections))),
					"maxConnections":         llx.IntData(int64(tea.Int32Value(srv.MaxConnections))),
					"dnsServers":             llx.StringDataPtr(srv.DnsServers),
					"multiFactorAuthEnabled": llx.BoolData(tea.BoolValue(srv.EnableMultiFactorAuth)),
					"idaasInstanceId":        llx.StringDataPtr(srv.IDaaSInstanceId),
					"idaasRegionId":          llx.StringDataPtr(srv.IDaaSRegionId),
					"createTime":             llx.TimeDataPtr(epochSeconds(srv.CreateTime)),
					"resourceGroupId":        llx.StringDataPtr(srv.ResourceGroupId),
				})
				if err != nil {
					return nil, err
				}
				mqlServer := resource.(*mqlAlicloudVpcSslVpnServer)
				mqlServer.region = region
				mqlServer.vpnGatewayID = tea.StringValue(srv.VpnGatewayId)
				res = append(res, mqlServer)
			}
			collected += int32(len(items))
			if len(items) == 0 || collected >= tea.Int32Value(resp.Body.TotalCount) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// vpnGateway resolves the gateway hosting the server.
func (r *mqlAlicloudVpcSslVpnServer) vpnGateway() (*mqlAlicloudVpcVpnGateway, error) {
	if r.vpnGatewayID == "" {
		r.VpnGateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	gateway := findVpnGateway(r.MqlRuntime, r.region, r.vpnGatewayID)
	if gateway == nil {
		r.VpnGateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return gateway, nil
}

// findVpnGateway locates a VPN gateway in the account-wide listing, which the
// runtime caches after the first read, so a query over every SSL VPN server
// costs one walk rather than a lookup per server.
func findVpnGateway(runtime *plugin.Runtime, region, gatewayID string) *mqlAlicloudVpcVpnGateway {
	vpc, err := CreateResource(runtime, "alicloud.vpc", map[string]*llx.RawData{})
	if err != nil {
		return nil
	}
	gateways := vpc.(*mqlAlicloudVpc).GetVpnGateways()
	if gateways.Error != nil {
		log.Debug().Err(gateways.Error).Msg("alicloud> could not resolve a VPN gateway")
		return nil
	}
	for _, entry := range gateways.Data {
		gateway, ok := entry.(*mqlAlicloudVpcVpnGateway)
		if ok && gateway.VpnGatewayId.Data == gatewayID && gateway.RegionId.Data == region {
			return gateway
		}
	}
	return nil
}

// sslVpnServers lists the SSL VPN servers hosted on this gateway, filtered out
// of the account-wide listing.
func (r *mqlAlicloudVpcVpnGateway) sslVpnServers() ([]any, error) {
	vpc, err := CreateResource(r.MqlRuntime, "alicloud.vpc", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	servers := vpc.(*mqlAlicloudVpc).GetSslVpnServers()
	if servers.Error != nil {
		return nil, servers.Error
	}

	res := []any{}
	for _, entry := range servers.Data {
		server, ok := entry.(*mqlAlicloudVpcSslVpnServer)
		if !ok {
			continue
		}
		if server.VpnGatewayId.Data == r.VpnGatewayId.Data && server.RegionId.Data == r.RegionId.Data {
			res = append(res, server)
		}
	}
	return res, nil
}

// clientCerts lists the client certificates issued for the server. Only the
// certificate metadata is read: DescribeSslVpnClientCerts returns no key
// material, unlike the singular DescribeSslVpnClientCert, which returns the
// client private key and is deliberately not called.
func (r *mqlAlicloudVpcSslVpnServer) clientCerts() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.VpcClient(r.region)
	if err != nil {
		return nil, err
	}

	res := []any{}
	pageNumber := int32(1)
	collected := int32(0)
	for {
		resp, err := client.DescribeSslVpnClientCerts(&vpcclient.DescribeSslVpnClientCertsRequest{
			RegionId:       tea.String(r.region),
			SslVpnServerId: tea.String(r.SslVpnServerId.Data),
			PageNumber:     tea.Int32(pageNumber),
			PageSize:       tea.Int32(vpcHybridPageSize),
		})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil || resp.Body.SslVpnClientCertKeys == nil {
			break
		}
		items := resp.Body.SslVpnClientCertKeys.SslVpnClientCertKey
		for _, cert := range items {
			if cert == nil || cert.SslVpnClientCertId == nil {
				continue
			}
			resource, err := CreateResource(r.MqlRuntime, "alicloud.vpc.sslVpnClientCert", map[string]*llx.RawData{
				"__id":               llx.StringDataPtr(cert.SslVpnClientCertId),
				"regionId":           llx.StringData(r.region),
				"sslVpnClientCertId": llx.StringDataPtr(cert.SslVpnClientCertId),
				"name":               llx.StringDataPtr(cert.Name),
				"sslVpnServerId":     llx.StringDataPtr(cert.SslVpnServerId),
				"status":             llx.StringDataPtr(cert.Status),
				"createTime":         llx.TimeDataPtr(epochSeconds(cert.CreateTime)),
				"endTime":            llx.TimeDataPtr(epochSeconds(cert.EndTime)),
				"resourceGroupId":    llx.StringDataPtr(cert.ResourceGroupId),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}
		collected += int32(len(items))
		if len(items) == 0 || collected >= tea.Int32Value(resp.Body.TotalCount) {
			break
		}
		pageNumber++
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// customer gateways
// ---------------------------------------------------------------------------

func (r *mqlAlicloudVpcCustomerGateway) id() (string, error) {
	return r.CustomerGatewayId.Data, nil
}

func (r *mqlAlicloudVpcCustomerGateway) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

// customerGateways enumerates the remote ends registered for site-to-site VPN
// tunnels.
func (r *mqlAlicloudVpc) customerGateways() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.VpcClient(region)
		if err != nil {
			return nil, err
		}

		pageNumber := int32(1)
		collected := int32(0)
		for {
			resp, err := client.DescribeCustomerGateways(&vpcclient.DescribeCustomerGatewaysRequest{
				RegionId:   tea.String(region),
				PageNumber: tea.Int32(pageNumber),
				PageSize:   tea.Int32(vpcHybridPageSize),
			})
			if err != nil {
				log.Debug().Err(err).Str("region", region).
					Msg("alicloud> could not list VPN customer gateways")
				break
			}
			if resp == nil || resp.Body == nil || resp.Body.CustomerGateways == nil {
				break
			}
			items := resp.Body.CustomerGateways.CustomerGateway
			for _, gw := range items {
				if gw == nil || gw.CustomerGatewayId == nil {
					continue
				}
				tags := map[string]any{}
				if gw.Tags != nil {
					for _, t := range gw.Tags.Tag {
						if t == nil || t.Key == nil {
							continue
						}
						tags[tea.StringValue(t.Key)] = tea.StringValue(t.Value)
					}
				}
				resource, err := CreateResource(r.MqlRuntime, "alicloud.vpc.customerGateway", map[string]*llx.RawData{
					"__id":              llx.StringDataPtr(gw.CustomerGatewayId),
					"regionId":          llx.StringData(region),
					"customerGatewayId": llx.StringDataPtr(gw.CustomerGatewayId),
					"name":              llx.StringDataPtr(gw.Name),
					"description":       llx.StringDataPtr(gw.Description),
					"ipAddress":         llx.StringDataPtr(gw.IpAddress),
					"asn":               llx.IntData(tea.Int64Value(gw.Asn)),
					// AuthKey is the BGP MD5 shared secret. Only whether one is
					// set reaches a scan result; the key itself never does.
					"authKeyConfigured": llx.BoolData(tea.StringValue(gw.AuthKey) != ""),
					"createTime":        llx.TimeDataPtr(epochSeconds(gw.CreateTime)),
					"resourceGroupId":   llx.StringDataPtr(gw.ResourceGroupId),
					"tags":              llx.MapData(tags, types.String),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, resource)
			}
			collected += int32(len(items))
			if len(items) == 0 || collected >= tea.Int32Value(resp.Body.TotalCount) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// lookupCustomerGateway finds a customer gateway by id in the account-wide
// listing, which is fetched once and cached, so a connection or tunnel resolves
// its remote end without a call of its own. It returns nil when the id is
// empty, when the listing cannot be read, and when no gateway carries the id.
func lookupCustomerGateway(runtime *plugin.Runtime, wanted string) *mqlAlicloudVpcCustomerGateway {
	if wanted == "" {
		return nil
	}
	vpc, err := CreateResource(runtime, "alicloud.vpc", map[string]*llx.RawData{})
	if err != nil {
		return nil
	}
	gateways := vpc.(*mqlAlicloudVpc).GetCustomerGateways()
	if gateways.Error != nil {
		log.Debug().Err(gateways.Error).Msg("alicloud> could not resolve a VPN customer gateway")
		return nil
	}
	for _, entry := range gateways.Data {
		gateway, ok := entry.(*mqlAlicloudVpcCustomerGateway)
		if ok && gateway.CustomerGatewayId.Data == wanted {
			return gateway
		}
	}
	return nil
}

// customerGateway resolves the remote end of the tunnel out of the account-wide
// customer gateway listing.
func (r *mqlAlicloudVpcVpnConnection) customerGateway() (*mqlAlicloudVpcCustomerGateway, error) {
	gateway := lookupCustomerGateway(r.MqlRuntime, r.CustomerGatewayId.Data)
	if gateway == nil {
		r.CustomerGateway.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return gateway, nil
}

// ---------------------------------------------------------------------------
// Express Connect
// ---------------------------------------------------------------------------

func (r *mqlAlicloudVpcPhysicalConnection) id() (string, error) {
	return r.PhysicalConnectionId.Data, nil
}

func (r *mqlAlicloudVpcVirtualBorderRouter) id() (string, error) {
	return r.VbrId.Data, nil
}

func (r *mqlAlicloudVpcPhysicalConnection) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

func (r *mqlAlicloudVpcVirtualBorderRouter) resourceGroup() (*mqlAlicloudResourceManagerResourceGroup, error) {
	return resolveResourceGroup(r.MqlRuntime, r.ResourceGroupId.Data, &r.ResourceGroup)
}

// physicalConnections enumerates the account's Express Connect circuits.
func (r *mqlAlicloudVpc) physicalConnections() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.VpcClient(region)
		if err != nil {
			return nil, err
		}

		pageNumber := int32(1)
		collected := int32(0)
		for {
			resp, err := client.DescribePhysicalConnections(&vpcclient.DescribePhysicalConnectionsRequest{
				RegionId:   tea.String(region),
				PageNumber: tea.Int32(pageNumber),
				PageSize:   tea.Int32(vpcHybridPageSize),
			})
			if err != nil {
				log.Debug().Err(err).Str("region", region).
					Msg("alicloud> could not list Express Connect physical connections")
				break
			}
			if resp == nil || resp.Body == nil || resp.Body.PhysicalConnectionSet == nil {
				break
			}
			items := resp.Body.PhysicalConnectionSet.PhysicalConnectionType
			for _, pc := range items {
				if pc == nil || pc.PhysicalConnectionId == nil {
					continue
				}
				tags := map[string]any{}
				if pc.Tags != nil {
					for _, t := range pc.Tags.Tags {
						if t == nil || t.Key == nil {
							continue
						}
						tags[tea.StringValue(t.Key)] = tea.StringValue(t.Value)
					}
				}
				resource, err := CreateResource(r.MqlRuntime, "alicloud.vpc.physicalConnection", map[string]*llx.RawData{
					"__id":                          llx.StringDataPtr(pc.PhysicalConnectionId),
					"regionId":                      llx.StringData(region),
					"physicalConnectionId":          llx.StringDataPtr(pc.PhysicalConnectionId),
					"name":                          llx.StringDataPtr(pc.Name),
					"description":                   llx.StringDataPtr(pc.Description),
					"status":                        llx.StringDataPtr(pc.Status),
					"businessStatus":                llx.StringDataPtr(pc.BusinessStatus),
					"bandwidth":                     llx.IntData(tea.Int64Value(pc.Bandwidth)),
					"lineOperator":                  llx.StringDataPtr(pc.LineOperator),
					"portType":                      llx.StringDataPtr(pc.PortType),
					"accessPointId":                 llx.StringDataPtr(pc.AccessPointId),
					"peerLocation":                  llx.StringDataPtr(pc.PeerLocation),
					"circuitCode":                   llx.StringDataPtr(pc.CircuitCode),
					"spec":                          llx.StringDataPtr(pc.Spec),
					"type":                          llx.StringDataPtr(pc.Type),
					"redundantPhysicalConnectionId": llx.StringDataPtr(pc.RedundantPhysicalConnectionId),
					"parentPhysicalConnectionId":    llx.StringDataPtr(pc.ParentPhysicalConnectionId),
					"creationTime":                  llx.TimeDataPtr(parseEcsTime(pc.CreationTime)),
					"enabledTime":                   llx.TimeDataPtr(parseEcsTime(pc.EnabledTime)),
					"endTime":                       llx.TimeDataPtr(parseEcsTime(pc.EndTime)),
					"resourceGroupId":               llx.StringDataPtr(pc.ResourceGroupId),
					"tags":                          llx.MapData(tags, types.String),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, resource)
			}
			collected += int32(len(items))
			if len(items) == 0 || collected >= tea.Int32Value(resp.Body.TotalCount) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// virtualBorderRouters enumerates the account's virtual border routers.
func (r *mqlAlicloudVpc) virtualBorderRouters() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.VpcClient(region)
		if err != nil {
			return nil, err
		}

		pageNumber := int32(1)
		collected := int32(0)
		for {
			resp, err := client.DescribeVirtualBorderRouters(&vpcclient.DescribeVirtualBorderRoutersRequest{
				RegionId:   tea.String(region),
				PageNumber: tea.Int32(pageNumber),
				PageSize:   tea.Int32(vpcHybridPageSize),
			})
			if err != nil {
				log.Debug().Err(err).Str("region", region).
					Msg("alicloud> could not list virtual border routers")
				break
			}
			if resp == nil || resp.Body == nil || resp.Body.VirtualBorderRouterSet == nil {
				break
			}
			items := resp.Body.VirtualBorderRouterSet.VirtualBorderRouterType
			for _, vbr := range items {
				if vbr == nil || vbr.VbrId == nil {
					continue
				}
				tags := map[string]any{}
				if vbr.Tags != nil {
					for _, t := range vbr.Tags.Tags {
						if t == nil || t.Key == nil {
							continue
						}
						tags[tea.StringValue(t.Key)] = tea.StringValue(t.Value)
					}
				}
				ownerUID := tea.StringValue(vbr.PhysicalConnectionOwnerUid)
				resource, err := CreateResource(r.MqlRuntime, "alicloud.vpc.virtualBorderRouter", map[string]*llx.RawData{
					"__id":                       llx.StringDataPtr(vbr.VbrId),
					"regionId":                   llx.StringData(region),
					"vbrId":                      llx.StringDataPtr(vbr.VbrId),
					"name":                       llx.StringDataPtr(vbr.Name),
					"description":                llx.StringDataPtr(vbr.Description),
					"status":                     llx.StringDataPtr(vbr.Status),
					"vlanId":                     llx.IntData(int64(tea.Int32Value(vbr.VlanId))),
					"physicalConnectionId":       llx.StringDataPtr(vbr.PhysicalConnectionId),
					"physicalConnectionStatus":   llx.StringDataPtr(vbr.PhysicalConnectionStatus),
					"physicalConnectionOwnerUid": llx.StringData(ownerUID),
					"localGatewayIp":             llx.StringDataPtr(vbr.LocalGatewayIp),
					"peerGatewayIp":              llx.StringDataPtr(vbr.PeerGatewayIp),
					"peeringSubnetMask":          llx.StringDataPtr(vbr.PeeringSubnetMask),
					"enableIpv6":                 llx.BoolData(tea.BoolValue(vbr.EnableIpv6)),
					"localIpv6GatewayIp":         llx.StringDataPtr(vbr.LocalIpv6GatewayIp),
					"peerIpv6GatewayIp":          llx.StringDataPtr(vbr.PeerIpv6GatewayIp),
					"bandwidth":                  llx.IntData(int64(tea.Int32Value(vbr.Bandwidth))),
					"mtu":                        llx.IntData(int64(tea.Int32Value(vbr.Mtu))),
					"detectMultiplier":           llx.IntData(tea.Int64Value(vbr.DetectMultiplier)),
					"minRxInterval":              llx.IntData(tea.Int64Value(vbr.MinRxInterval)),
					"minTxInterval":              llx.IntData(tea.Int64Value(vbr.MinTxInterval)),
					"routeTableId":               llx.StringDataPtr(vbr.RouteTableId),
					"type":                       llx.StringDataPtr(vbr.Type),
					"creationTime":               llx.TimeDataPtr(parseEcsTime(vbr.CreationTime)),
					"activationTime":             llx.TimeDataPtr(parseEcsTime(vbr.ActivationTime)),
					"terminationTime":            llx.TimeDataPtr(parseEcsTime(vbr.TerminationTime)),
					"resourceGroupId":            llx.StringDataPtr(vbr.ResourceGroupId),
					"tags":                       llx.MapData(tags, types.String),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, resource)
			}
			collected += int32(len(items))
			if len(items) == 0 || collected >= tea.Int32Value(resp.Body.TotalCount) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// vbrCrossAccount reports whether an attached Express Connect circuit belongs
// to a different account than the one being scanned. An owner id that is
// missing on either side is not evidence of a third-party circuit, so the
// router reads as same-account: reporting a hosted connection that may not
// exist is worse than missing one.
func vbrCrossAccount(connectionOwner, scannedAccount string) bool {
	if connectionOwner == "" || scannedAccount == "" {
		return false
	}
	return connectionOwner != scannedAccount
}

// crossAccountConnection reports whether the attached circuit belongs to
// another account, which is the hosted Express Connect arrangement: the
// physical path is then under a third party's control.
func (r *mqlAlicloudVpcVirtualBorderRouter) crossAccountConnection() (bool, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	return vbrCrossAccount(r.PhysicalConnectionOwnerUid.Data, conn.AccountID()), nil
}

// physicalConnection resolves the circuit the router attaches to.
func (r *mqlAlicloudVpcVirtualBorderRouter) physicalConnection() (*mqlAlicloudVpcPhysicalConnection, error) {
	connection := r.findPhysicalConnection()
	if connection == nil {
		r.PhysicalConnection.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return connection, nil
}

// findPhysicalConnection locates the attached circuit in the account-wide
// listing, which the runtime caches after the first read.
func (r *mqlAlicloudVpcVirtualBorderRouter) findPhysicalConnection() *mqlAlicloudVpcPhysicalConnection {
	wanted := r.PhysicalConnectionId.Data
	if wanted == "" {
		return nil
	}
	vpc, err := CreateResource(r.MqlRuntime, "alicloud.vpc", map[string]*llx.RawData{})
	if err != nil {
		return nil
	}
	connections := vpc.(*mqlAlicloudVpc).GetPhysicalConnections()
	if connections.Error != nil {
		log.Debug().Err(connections.Error).Msg("alicloud> could not resolve an Express Connect circuit")
		return nil
	}
	for _, entry := range connections.Data {
		pc, ok := entry.(*mqlAlicloudVpcPhysicalConnection)
		if ok && pc.PhysicalConnectionId.Data == wanted {
			return pc
		}
	}
	return nil
}

// virtualBorderRouters lists the routers attached to this circuit, filtered out
// of the account-wide listing.
func (r *mqlAlicloudVpcPhysicalConnection) virtualBorderRouters() ([]any, error) {
	vpc, err := CreateResource(r.MqlRuntime, "alicloud.vpc", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	routers := vpc.(*mqlAlicloudVpc).GetVirtualBorderRouters()
	if routers.Error != nil {
		return nil, routers.Error
	}

	res := []any{}
	for _, entry := range routers.Data {
		router, ok := entry.(*mqlAlicloudVpcVirtualBorderRouter)
		if ok && router.PhysicalConnectionId.Data == r.PhysicalConnectionId.Data {
			res = append(res, router)
		}
	}
	return res, nil
}
