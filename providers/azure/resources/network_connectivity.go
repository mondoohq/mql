// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// -----------------------------------------------------------------------------
// Virtual WAN VPN gateways (site-to-site)
// -----------------------------------------------------------------------------

type mqlAzureSubscriptionNetworkServiceVpnGatewayInternal struct {
	cacheVirtualHubId *string
	cacheBgpSettings  *network.BgpSettings
	cacheConnections  []*network.VPNConnection
}

func (a *mqlAzureSubscriptionNetworkService) vpnGateways() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := network.NewVPNGatewaysClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(&network.VPNGatewaysClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, gw := range page.Value {
			if gw == nil {
				continue
			}
			mqlGw, err := azureVpnGatewayToMql(a.MqlRuntime, gw)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlGw)
		}
	}
	return res, nil
}

func azureVpnGatewayToMql(runtime *plugin.Runtime, gw *network.VPNGateway) (*mqlAzureSubscriptionNetworkServiceVpnGateway, error) {
	var provisioningState string
	var scaleUnit int64
	var bgpRouteTranslation, routingPreferenceInternet bool
	if gw.Properties != nil {
		if gw.Properties.ProvisioningState != nil {
			provisioningState = string(*gw.Properties.ProvisioningState)
		}
		if gw.Properties.VPNGatewayScaleUnit != nil {
			scaleUnit = int64(*gw.Properties.VPNGatewayScaleUnit)
		}
		bgpRouteTranslation = convert.ToValue(gw.Properties.EnableBgpRouteTranslationForNat)
		routingPreferenceInternet = convert.ToValue(gw.Properties.IsRoutingPreferenceInternet)
	}
	mqlGw, err := CreateResource(runtime, "azure.subscription.networkService.vpnGateway",
		map[string]*llx.RawData{
			"id":                               llx.StringDataPtr(gw.ID),
			"name":                             llx.StringDataPtr(gw.Name),
			"location":                         llx.StringDataPtr(gw.Location),
			"tags":                             llx.MapData(convert.PtrMapStrToInterface(gw.Tags), types.String),
			"type":                             llx.StringDataPtr(gw.Type),
			"etag":                             llx.StringDataPtr(gw.Etag),
			"provisioningState":                llx.StringData(provisioningState),
			"scaleUnit":                        llx.IntData(scaleUnit),
			"bgpRouteTranslationForNatEnabled": llx.BoolData(bgpRouteTranslation),
			"routingPreferenceInternet":        llx.BoolData(routingPreferenceInternet),
		})
	if err != nil {
		return nil, err
	}
	res := mqlGw.(*mqlAzureSubscriptionNetworkServiceVpnGateway)
	if gw.Properties != nil {
		if gw.Properties.VirtualHub != nil {
			res.cacheVirtualHubId = gw.Properties.VirtualHub.ID
		}
		res.cacheBgpSettings = gw.Properties.BgpSettings
		res.cacheConnections = gw.Properties.Connections
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVpnGateway) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVpnGateway) virtualHub() (*mqlAzureSubscriptionNetworkServiceVirtualHub, error) {
	if a.cacheVirtualHubId == nil || *a.cacheVirtualHubId == "" {
		a.VirtualHub.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.virtualHub", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cacheVirtualHubId),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionNetworkServiceVirtualHub), nil
}

func (a *mqlAzureSubscriptionNetworkServiceVpnGateway) bgpSettings() (*mqlAzureSubscriptionNetworkServiceBgpSettings, error) {
	if a.cacheBgpSettings == nil {
		a.BgpSettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return mqlBgpSettingsFromSdk(a.MqlRuntime, a.Id.Data, a.cacheBgpSettings)
}

func (a *mqlAzureSubscriptionNetworkServiceVpnGateway) connections() ([]any, error) {
	res := []any{}
	for _, c := range a.cacheConnections {
		if c == nil {
			continue
		}
		mqlConn, err := azureVpnConnectionToMql(a.MqlRuntime, c)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlConn)
	}
	return res, nil
}

type mqlAzureSubscriptionNetworkServiceVpnGatewayConnectionInternal struct {
	cacheRemoteVpnSiteId *string
}

func azureVpnConnectionToMql(runtime *plugin.Runtime, c *network.VPNConnection) (*mqlAzureSubscriptionNetworkServiceVpnGatewayConnection, error) {
	var connectionStatus, protocol string
	var bandwidthMbps, routingWeight, ingress, egress int64
	var bgpEnabled, internetSecurity bool
	var remoteVpnSiteId *string
	if p := c.Properties; p != nil {
		if p.ConnectionStatus != nil {
			connectionStatus = string(*p.ConnectionStatus)
		}
		if p.VPNConnectionProtocolType != nil {
			protocol = string(*p.VPNConnectionProtocolType)
		}
		if p.ConnectionBandwidth != nil {
			bandwidthMbps = int64(*p.ConnectionBandwidth)
		}
		if p.RoutingWeight != nil {
			routingWeight = int64(*p.RoutingWeight)
		}
		if p.IngressBytesTransferred != nil {
			ingress = *p.IngressBytesTransferred
		}
		if p.EgressBytesTransferred != nil {
			egress = *p.EgressBytesTransferred
		}
		bgpEnabled = convert.ToValue(p.EnableBgp)
		internetSecurity = convert.ToValue(p.EnableInternetSecurity)
		if p.RemoteVPNSite != nil {
			remoteVpnSiteId = p.RemoteVPNSite.ID
		}
	}
	mqlConn, err := CreateResource(runtime, "azure.subscription.networkService.vpnGateway.connection",
		map[string]*llx.RawData{
			"id":                      llx.StringDataPtr(c.ID),
			"name":                    llx.StringDataPtr(c.Name),
			"etag":                    llx.StringDataPtr(c.Etag),
			"connectionStatus":        llx.StringData(connectionStatus),
			"bandwidthMbps":           llx.IntData(bandwidthMbps),
			"bgpEnabled":              llx.BoolData(bgpEnabled),
			"internetSecurityEnabled": llx.BoolData(internetSecurity),
			"routingWeight":           llx.IntData(routingWeight),
			"protocol":                llx.StringData(protocol),
			"ingressBytesTransferred": llx.IntData(ingress),
			"egressBytesTransferred":  llx.IntData(egress),
		})
	if err != nil {
		return nil, err
	}
	res := mqlConn.(*mqlAzureSubscriptionNetworkServiceVpnGatewayConnection)
	res.cacheRemoteVpnSiteId = remoteVpnSiteId
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVpnGatewayConnection) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVpnGatewayConnection) remoteVpnSite() (*mqlAzureSubscriptionNetworkServiceVpnSite, error) {
	if a.cacheRemoteVpnSiteId == nil || *a.cacheRemoteVpnSiteId == "" {
		a.RemoteVpnSite.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.vpnSite", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cacheRemoteVpnSiteId),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionNetworkServiceVpnSite), nil
}

// -----------------------------------------------------------------------------
// Point-to-site VPN server configurations
// -----------------------------------------------------------------------------

func (a *mqlAzureSubscriptionNetworkService) vpnServerConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := network.NewVPNServerConfigurationsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(&network.VPNServerConfigurationsClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, cfg := range page.Value {
			if cfg == nil {
				continue
			}
			vpnProtocols := []any{}
			authTypes := []any{}
			var radiusServerAddress, provisioningState string
			if p := cfg.Properties; p != nil {
				// ProvisioningState is *string here (unlike the *ProvisioningState
				// enum on the other resources), but use the same nil-check + deref
				// shape for consistency.
				if p.ProvisioningState != nil {
					provisioningState = *p.ProvisioningState
				}
				radiusServerAddress = convert.ToValue(p.RadiusServerAddress)
				for _, proto := range p.VPNProtocols {
					if proto != nil {
						vpnProtocols = append(vpnProtocols, string(*proto))
					}
				}
				for _, at := range p.VPNAuthenticationTypes {
					if at != nil {
						authTypes = append(authTypes, string(*at))
					}
				}
			}
			mqlCfg, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.vpnServerConfiguration",
				map[string]*llx.RawData{
					"id":                  llx.StringDataPtr(cfg.ID),
					"name":                llx.StringDataPtr(cfg.Name),
					"location":            llx.StringDataPtr(cfg.Location),
					"tags":                llx.MapData(convert.PtrMapStrToInterface(cfg.Tags), types.String),
					"type":                llx.StringDataPtr(cfg.Type),
					"etag":                llx.StringDataPtr(cfg.Etag),
					"provisioningState":   llx.StringData(provisioningState),
					"vpnProtocols":        llx.ArrayData(vpnProtocols, types.String),
					"authenticationTypes": llx.ArrayData(authTypes, types.String),
					"radiusServerAddress": llx.StringData(radiusServerAddress),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlCfg)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVpnServerConfiguration) id() (string, error) {
	return a.Id.Data, nil
}

// -----------------------------------------------------------------------------
// Virtual WAN ExpressRoute gateways
// -----------------------------------------------------------------------------

type mqlAzureSubscriptionNetworkServiceExpressRouteGatewayInternal struct {
	cacheVirtualHubId *string
	cacheConnections  []*network.ExpressRouteConnection
}

func (a *mqlAzureSubscriptionNetworkService) expressRouteGateways() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := network.NewExpressRouteGatewaysClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	// ExpressRoute gateways expose a single (non-paged) subscription-wide list.
	resp, err := client.ListBySubscription(ctx, &network.ExpressRouteGatewaysClientListBySubscriptionOptions{})
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, gw := range resp.Value {
		if gw == nil {
			continue
		}
		mqlGw, err := azureExpressRouteGatewayToMql(a.MqlRuntime, gw)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGw)
	}
	return res, nil
}

func azureExpressRouteGatewayToMql(runtime *plugin.Runtime, gw *network.ExpressRouteGateway) (*mqlAzureSubscriptionNetworkServiceExpressRouteGateway, error) {
	var provisioningState string
	var allowNonVwan bool
	var minScaleUnits, maxScaleUnits int64
	if p := gw.Properties; p != nil {
		if p.ProvisioningState != nil {
			provisioningState = string(*p.ProvisioningState)
		}
		allowNonVwan = convert.ToValue(p.AllowNonVirtualWanTraffic)
		minScaleUnits, maxScaleUnits = expressRouteGatewayScaleBounds(p.AutoScaleConfiguration)
	}
	mqlGw, err := CreateResource(runtime, "azure.subscription.networkService.expressRouteGateway",
		map[string]*llx.RawData{
			"id":                        llx.StringDataPtr(gw.ID),
			"name":                      llx.StringDataPtr(gw.Name),
			"location":                  llx.StringDataPtr(gw.Location),
			"tags":                      llx.MapData(convert.PtrMapStrToInterface(gw.Tags), types.String),
			"type":                      llx.StringDataPtr(gw.Type),
			"etag":                      llx.StringDataPtr(gw.Etag),
			"provisioningState":         llx.StringData(provisioningState),
			"allowNonVirtualWanTraffic": llx.BoolData(allowNonVwan),
			"minScaleUnits":             llx.IntData(minScaleUnits),
			"maxScaleUnits":             llx.IntData(maxScaleUnits),
		})
	if err != nil {
		return nil, err
	}
	res := mqlGw.(*mqlAzureSubscriptionNetworkServiceExpressRouteGateway)
	if p := gw.Properties; p != nil {
		if p.VirtualHub != nil {
			res.cacheVirtualHubId = p.VirtualHub.ID
		}
		res.cacheConnections = p.ExpressRouteConnections
	}
	return res, nil
}

// expressRouteGatewayScaleBounds extracts the min/max auto-scale units from an
// ExpressRoute gateway's auto-scale configuration, tolerating a nil config, nil
// bounds, or nil min/max (each yields 0).
func expressRouteGatewayScaleBounds(cfg *network.ExpressRouteGatewayPropertiesAutoScaleConfiguration) (min, max int64) {
	if cfg == nil || cfg.Bounds == nil {
		return 0, 0
	}
	if cfg.Bounds.Min != nil {
		min = int64(*cfg.Bounds.Min)
	}
	if cfg.Bounds.Max != nil {
		max = int64(*cfg.Bounds.Max)
	}
	return min, max
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteGateway) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteGateway) virtualHub() (*mqlAzureSubscriptionNetworkServiceVirtualHub, error) {
	if a.cacheVirtualHubId == nil || *a.cacheVirtualHubId == "" {
		a.VirtualHub.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.virtualHub", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cacheVirtualHubId),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionNetworkServiceVirtualHub), nil
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteGateway) connections() ([]any, error) {
	res := []any{}
	for _, c := range a.cacheConnections {
		if c == nil {
			continue
		}
		var provisioningState, peeringId string
		var routingWeight int64
		var internetSecurity, gatewayBypass bool
		if p := c.Properties; p != nil {
			if p.ProvisioningState != nil {
				provisioningState = string(*p.ProvisioningState)
			}
			if p.RoutingWeight != nil {
				routingWeight = int64(*p.RoutingWeight)
			}
			internetSecurity = convert.ToValue(p.EnableInternetSecurity)
			gatewayBypass = convert.ToValue(p.ExpressRouteGatewayBypass)
			if p.ExpressRouteCircuitPeering != nil {
				peeringId = convert.ToValue(p.ExpressRouteCircuitPeering.ID)
			}
		}
		mqlConn, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.expressRouteGateway.connection",
			map[string]*llx.RawData{
				"id":                           llx.StringDataPtr(c.ID),
				"name":                         llx.StringDataPtr(c.Name),
				"provisioningState":            llx.StringData(provisioningState),
				"routingWeight":                llx.IntData(routingWeight),
				"internetSecurityEnabled":      llx.BoolData(internetSecurity),
				"expressRouteGatewayBypass":    llx.BoolData(gatewayBypass),
				"expressRouteCircuitPeeringId": llx.StringData(peeringId),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlConn)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteGatewayConnection) id() (string, error) {
	return a.Id.Data, nil
}

// -----------------------------------------------------------------------------
// ExpressRoute Direct ports
// -----------------------------------------------------------------------------

type mqlAzureSubscriptionNetworkServiceExpressRoutePortInternal struct {
	cacheCircuitIds []string
}

func (a *mqlAzureSubscriptionNetworkService) expressRoutePorts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := network.NewExpressRoutePortsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(&network.ExpressRoutePortsClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, port := range page.Value {
			if port == nil {
				continue
			}
			mqlPort, err := azureExpressRoutePortToMql(a.MqlRuntime, port)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPort)
		}
	}
	return res, nil
}

func azureExpressRoutePortToMql(runtime *plugin.Runtime, port *network.ExpressRoutePort) (*mqlAzureSubscriptionNetworkServiceExpressRoutePort, error) {
	var provisioningState, encapsulation, billingType, peeringLocation, mtu, etherType, resourceGuid string
	var bandwidthInGbps int64
	var provisionedBandwidth float64
	links := []any{}
	var circuitIds []string
	if p := port.Properties; p != nil {
		if p.ProvisioningState != nil {
			provisioningState = string(*p.ProvisioningState)
		}
		if p.Encapsulation != nil {
			encapsulation = string(*p.Encapsulation)
		}
		if p.BillingType != nil {
			billingType = string(*p.BillingType)
		}
		peeringLocation = convert.ToValue(p.PeeringLocation)
		mtu = convert.ToValue(p.Mtu)
		etherType = convert.ToValue(p.EtherType)
		resourceGuid = convert.ToValue(p.ResourceGUID)
		if p.BandwidthInGbps != nil {
			bandwidthInGbps = int64(*p.BandwidthInGbps)
		}
		if p.ProvisionedBandwidthInGbps != nil {
			provisionedBandwidth = float64(*p.ProvisionedBandwidthInGbps)
		}
		linkDicts, err := convert.JsonToDictSlice(p.Links)
		if err != nil {
			return nil, err
		}
		links = linkDicts
		circuitIds = azureNetworkSubResourceIDs(p.Circuits)
	}
	mqlPort, err := CreateResource(runtime, "azure.subscription.networkService.expressRoutePort",
		map[string]*llx.RawData{
			"id":                         llx.StringDataPtr(port.ID),
			"name":                       llx.StringDataPtr(port.Name),
			"location":                   llx.StringDataPtr(port.Location),
			"tags":                       llx.MapData(convert.PtrMapStrToInterface(port.Tags), types.String),
			"type":                       llx.StringDataPtr(port.Type),
			"etag":                       llx.StringDataPtr(port.Etag),
			"provisioningState":          llx.StringData(provisioningState),
			"bandwidthInGbps":            llx.IntData(bandwidthInGbps),
			"provisionedBandwidthInGbps": llx.FloatData(provisionedBandwidth),
			"encapsulation":              llx.StringData(encapsulation),
			"billingType":                llx.StringData(billingType),
			"peeringLocation":            llx.StringData(peeringLocation),
			"mtu":                        llx.StringData(mtu),
			"etherType":                  llx.StringData(etherType),
			"resourceGuid":               llx.StringData(resourceGuid),
			"links":                      llx.ArrayData(links, types.Dict),
		})
	if err != nil {
		return nil, err
	}
	res := mqlPort.(*mqlAzureSubscriptionNetworkServiceExpressRoutePort)
	res.cacheCircuitIds = circuitIds
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRoutePort) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRoutePort) circuits() ([]any, error) {
	return azureResourceRefsByID(a.MqlRuntime, "azure.subscription.networkService.expressRouteCircuit", a.cacheCircuitIds)
}

// -----------------------------------------------------------------------------
// Route filters
// -----------------------------------------------------------------------------

type mqlAzureSubscriptionNetworkServiceRouteFilterInternal struct {
	cacheRules []*network.RouteFilterRule
}

func (a *mqlAzureSubscriptionNetworkService) routeFilters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := network.NewRouteFiltersClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(&network.RouteFiltersClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, rf := range page.Value {
			if rf == nil {
				continue
			}
			var provisioningState string
			var rules []*network.RouteFilterRule
			if p := rf.Properties; p != nil {
				if p.ProvisioningState != nil {
					provisioningState = string(*p.ProvisioningState)
				}
				rules = p.Rules
			}
			mqlRf, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.routeFilter",
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(rf.ID),
					"name":              llx.StringDataPtr(rf.Name),
					"location":          llx.StringDataPtr(rf.Location),
					"tags":              llx.MapData(convert.PtrMapStrToInterface(rf.Tags), types.String),
					"type":              llx.StringDataPtr(rf.Type),
					"etag":              llx.StringDataPtr(rf.Etag),
					"provisioningState": llx.StringData(provisioningState),
				})
			if err != nil {
				return nil, err
			}
			mqlRf.(*mqlAzureSubscriptionNetworkServiceRouteFilter).cacheRules = rules
			res = append(res, mqlRf)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceRouteFilter) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceRouteFilter) rules() ([]any, error) {
	res := []any{}
	for _, rule := range a.cacheRules {
		if rule == nil {
			continue
		}
		var access, ruleType, provisioningState string
		communities := []any{}
		if p := rule.Properties; p != nil {
			if p.Access != nil {
				access = string(*p.Access)
			}
			if p.RouteFilterRuleType != nil {
				ruleType = string(*p.RouteFilterRuleType)
			}
			if p.ProvisioningState != nil {
				provisioningState = string(*p.ProvisioningState)
			}
			for _, community := range p.Communities {
				if community != nil {
					communities = append(communities, *community)
				}
			}
		}
		mqlRule, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.routeFilter.rule",
			map[string]*llx.RawData{
				"id":                llx.StringDataPtr(rule.ID),
				"name":              llx.StringDataPtr(rule.Name),
				"location":          llx.StringDataPtr(rule.Location),
				"etag":              llx.StringDataPtr(rule.Etag),
				"provisioningState": llx.StringData(provisioningState),
				"access":            llx.StringData(access),
				"ruleType":          llx.StringData(ruleType),
				"communities":       llx.ArrayData(communities, types.String),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceRouteFilterRule) id() (string, error) {
	return a.Id.Data, nil
}
