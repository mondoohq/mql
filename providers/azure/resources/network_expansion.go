// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	trafficmanager "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/trafficmanager/armtrafficmanager"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// -----------------------------------------------------------------------------
// shared internal-struct fields for typed-ref caching
// -----------------------------------------------------------------------------

type mqlAzureSubscriptionNetworkServiceVirtualHubInternal struct {
	cacheVirtualWanId    *string
	cacheAzureFirewallId *string
}

type mqlAzureSubscriptionNetworkServiceVirtualHubVnetConnectionInternal struct {
	cacheRemoteVnetId *string
}

type mqlAzureSubscriptionNetworkServiceVirtualWanInternal struct {
	cacheVpnSiteIds    []string
	cacheVirtualHubIds []string
}

type mqlAzureSubscriptionNetworkServiceVpnSiteInternal struct {
	cacheVirtualWanId *string
}

// -----------------------------------------------------------------------------
// id() methods
// -----------------------------------------------------------------------------

func (a *mqlAzureSubscriptionNetworkServiceTrafficManagerProfile) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceTrafficManagerProfileEndpoint) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualWan) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualHub) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualHubRouteTable) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualHubVnetConnection) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteCircuit) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteCircuitPeering) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteCircuitAuthorization) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceWatcherPacketCapture) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceWatcherConnectionMonitor) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVpnSite) id() (string, error) {
	return a.Id.Data, nil
}

// -----------------------------------------------------------------------------
// Traffic Manager
// -----------------------------------------------------------------------------

func (a *mqlAzureSubscriptionNetworkService) trafficManagerProfiles() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId := a.SubscriptionId.Data

	client, err := trafficmanager.NewProfilesClient(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListBySubscriptionPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, profile := range page.Value {
			mql, err := azureTrafficManagerProfileToMql(a.MqlRuntime, profile)
			if err != nil {
				return nil, err
			}
			if mql != nil {
				res = append(res, mql)
			}
		}
	}
	return res, nil
}

// trafficManagerProfileEnabled reports whether the Traffic Manager profile is
// enabled. The SDK models this as an Enabled/Disabled enum; we collapse it to a
// bool where only the explicit Enabled state is true.
func trafficManagerProfileEnabled(props *trafficmanager.ProfileProperties) bool {
	return props != nil && props.ProfileStatus != nil && *props.ProfileStatus == trafficmanager.ProfileStatusEnabled
}

// trafficManagerEndpointEnabled reports whether the Traffic Manager endpoint is
// enabled. The SDK models this as an Enabled/Disabled enum; we collapse it to a
// bool where only the explicit Enabled state is true.
func trafficManagerEndpointEnabled(props *trafficmanager.EndpointProperties) bool {
	return props != nil && props.EndpointStatus != nil && *props.EndpointStatus == trafficmanager.EndpointStatusEnabled
}

func azureTrafficManagerProfileToMql(runtime *plugin.Runtime, p *trafficmanager.Profile) (plugin.Resource, error) {
	if p == nil {
		return nil, nil
	}
	properties, err := convert.JsonToDict(p.Properties)
	if err != nil {
		return nil, err
	}

	args := map[string]*llx.RawData{
		"id":                          llx.StringDataPtr(p.ID),
		"name":                        llx.StringDataPtr(p.Name),
		"location":                    llx.StringDataPtr(p.Location),
		"tags":                        llx.MapData(convert.PtrMapStrToInterface(p.Tags), types.String),
		"type":                        llx.StringDataPtr(p.Type),
		"properties":                  llx.DictData(properties),
		"status":                      llx.BoolData(false),
		"trafficRoutingMethod":        llx.StringDataPtr(nil),
		"trafficViewEnrollmentStatus": llx.StringDataPtr(nil),
		"maxReturn":                   llx.IntDataDefault[int64](nil, 0),
		"allowedEndpointRecordTypes":  llx.ArrayData([]any{}, types.String),
		"dnsConfig":                   llx.DictData(nil),
		"dnsSettings":                 llx.NilData,
		"monitorConfig":               llx.DictData(nil),
		"monitorSettings":             llx.NilData,
		"endpoints":                   llx.ArrayData([]any{}, types.Resource("azure.subscription.networkService.trafficManagerProfile.endpoint")),
	}

	props := p.Properties
	if props == nil {
		return CreateResource(runtime, "azure.subscription.networkService.trafficManagerProfile", args)
	}

	args["status"] = llx.BoolData(trafficManagerProfileEnabled(props))
	if props.TrafficRoutingMethod != nil {
		s := string(*props.TrafficRoutingMethod)
		args["trafficRoutingMethod"] = llx.StringData(s)
	}
	if props.TrafficViewEnrollmentStatus != nil {
		s := string(*props.TrafficViewEnrollmentStatus)
		args["trafficViewEnrollmentStatus"] = llx.StringData(s)
	}
	args["maxReturn"] = llx.IntDataDefault(props.MaxReturn, 0)

	recordTypes := []any{}
	for _, t := range props.AllowedEndpointRecordTypes {
		if t != nil {
			recordTypes = append(recordTypes, string(*t))
		}
	}
	args["allowedEndpointRecordTypes"] = llx.ArrayData(recordTypes, types.String)

	dnsDict, err := convert.JsonToDict(props.DNSConfig)
	if err != nil {
		return nil, err
	}
	args["dnsConfig"] = llx.DictData(dnsDict)

	// A profile ARM returns without a DNS config reports null rather than a
	// settings resource with a zero TTL, which would read as "never cache".
	if dns := props.DNSConfig; dns != nil {
		const dnsSettingsResource = "azure.subscription.networkService.trafficManagerProfile.dnsSettings"
		mqlDNS, err := CreateResource(runtime, dnsSettingsResource, map[string]*llx.RawData{
			"__id":         llx.StringData(convert.ToValue(p.ID) + "/dnsSettings"),
			"relativeName": llx.StringDataPtr(dns.RelativeName),
			"fqdn":         llx.StringDataPtr(dns.Fqdn),
			"ttl":          llx.IntDataPtr(dns.TTL),
		})
		if err != nil {
			return nil, err
		}
		args["dnsSettings"] = llx.ResourceData(mqlDNS, dnsSettingsResource)
	}

	monitorDict, err := convert.JsonToDict(props.MonitorConfig)
	if err != nil {
		return nil, err
	}
	args["monitorConfig"] = llx.DictData(monitorDict)

	// A profile with no monitoring configuration reports null rather than a
	// settings resource full of zeros, which would read as a probe on port 0.
	if props.MonitorConfig != nil {
		mc := props.MonitorConfig
		customHeaders := map[string]any{}
		for _, h := range mc.CustomHeaders {
			if h == nil || h.Name == nil {
				continue
			}
			customHeaders[*h.Name] = convert.ToValue(h.Value)
		}
		statusRanges := []any{}
		for _, r := range mc.ExpectedStatusCodeRanges {
			if r == nil {
				continue
			}
			d, err := convert.JsonToDict(r)
			if err != nil {
				return nil, err
			}
			statusRanges = append(statusRanges, d)
		}
		mqlMonitor, err := CreateResource(runtime, "azure.subscription.networkService.trafficManagerProfile.monitorSettings",
			map[string]*llx.RawData{
				"__id":                      llx.StringData(convert.ToValue(p.ID) + "/monitorSettings"),
				"protocol":                  llx.StringDataPtr(stringEnumPtr(mc.Protocol)),
				"port":                      llx.IntDataPtr(mc.Port),
				"path":                      llx.StringDataPtr(mc.Path),
				"intervalInSeconds":         llx.IntDataPtr(mc.IntervalInSeconds),
				"timeoutInSeconds":          llx.IntDataPtr(mc.TimeoutInSeconds),
				"toleratedNumberOfFailures": llx.IntDataPtr(mc.ToleratedNumberOfFailures),
				"profileMonitorStatus":      llx.StringDataPtr(stringEnumPtr(mc.ProfileMonitorStatus)),
				"customHeaders":             llx.MapData(customHeaders, types.String),
				"expectedStatusCodeRanges":  llx.ArrayData(statusRanges, types.Dict),
			})
		if err != nil {
			return nil, err
		}
		args["monitorSettings"] = llx.ResourceData(mqlMonitor, "azure.subscription.networkService.trafficManagerProfile.monitorSettings")
	}

	endpoints := []any{}
	for _, ep := range props.Endpoints {
		mqlEp, err := azureTrafficManagerEndpointToMql(runtime, ep)
		if err != nil {
			return nil, err
		}
		if mqlEp != nil {
			endpoints = append(endpoints, mqlEp)
		}
	}
	args["endpoints"] = llx.ArrayData(endpoints, types.Resource("azure.subscription.networkService.trafficManagerProfile.endpoint"))

	return CreateResource(runtime, "azure.subscription.networkService.trafficManagerProfile", args)
}

func azureTrafficManagerEndpointToMql(runtime *plugin.Runtime, ep *trafficmanager.Endpoint) (plugin.Resource, error) {
	if ep == nil {
		return nil, nil
	}
	properties, err := convert.JsonToDict(ep.Properties)
	if err != nil {
		return nil, err
	}

	args := map[string]*llx.RawData{
		"id":                    llx.StringDataPtr(ep.ID),
		"name":                  llx.StringDataPtr(ep.Name),
		"type":                  llx.StringDataPtr(ep.Type),
		"properties":            llx.DictData(properties),
		"alwaysServe":           llx.StringDataPtr(nil),
		"status":                llx.BoolData(false),
		"endpointMonitorStatus": llx.StringDataPtr(nil),
		"target":                llx.StringDataPtr(nil),
		"targetResourceId":      llx.StringDataPtr(nil),
		"endpointLocation":      llx.StringDataPtr(nil),
		"weight":                llx.IntDataDefault[int64](nil, 0),
		"priority":              llx.IntDataDefault[int64](nil, 0),
		"minChildEndpoints":     llx.IntDataDefault[int64](nil, 0),
		"minChildEndpointsIPv4": llx.IntDataDefault[int64](nil, 0),
		"minChildEndpointsIPv6": llx.IntDataDefault[int64](nil, 0),
		"geoMapping":            llx.ArrayData([]any{}, types.String),
		"subnets":               llx.ArrayData([]any{}, types.Dict),
		"customHeaders":         llx.ArrayData([]any{}, types.Dict),
	}

	props := ep.Properties
	if props == nil {
		return CreateResource(runtime, "azure.subscription.networkService.trafficManagerProfile.endpoint", args)
	}

	if props.AlwaysServe != nil {
		s := string(*props.AlwaysServe)
		args["alwaysServe"] = llx.StringData(s)
	}
	args["status"] = llx.BoolData(trafficManagerEndpointEnabled(props))
	if props.EndpointMonitorStatus != nil {
		s := string(*props.EndpointMonitorStatus)
		args["endpointMonitorStatus"] = llx.StringData(s)
	}
	args["target"] = llx.StringDataPtr(props.Target)
	args["targetResourceId"] = llx.StringDataPtr(props.TargetResourceID)
	args["endpointLocation"] = llx.StringDataPtr(props.EndpointLocation)
	args["weight"] = llx.IntDataDefault(props.Weight, 0)
	args["priority"] = llx.IntDataDefault(props.Priority, 0)
	args["minChildEndpoints"] = llx.IntDataDefault(props.MinChildEndpoints, 0)
	args["minChildEndpointsIPv4"] = llx.IntDataDefault(props.MinChildEndpointsIPv4, 0)
	args["minChildEndpointsIPv6"] = llx.IntDataDefault(props.MinChildEndpointsIPv6, 0)

	geo := []any{}
	for _, g := range props.GeoMapping {
		if g != nil {
			geo = append(geo, *g)
		}
	}
	args["geoMapping"] = llx.ArrayData(geo, types.String)

	subnets := []any{}
	for _, s := range props.Subnets {
		d, err := convert.JsonToDict(s)
		if err != nil {
			return nil, err
		}
		subnets = append(subnets, d)
	}
	args["subnets"] = llx.ArrayData(subnets, types.Dict)

	headers := []any{}
	for _, h := range props.CustomHeaders {
		d, err := convert.JsonToDict(h)
		if err != nil {
			return nil, err
		}
		headers = append(headers, d)
	}
	args["customHeaders"] = llx.ArrayData(headers, types.Dict)

	return CreateResource(runtime, "azure.subscription.networkService.trafficManagerProfile.endpoint", args)
}

// -----------------------------------------------------------------------------
// Virtual WAN
// -----------------------------------------------------------------------------

func (a *mqlAzureSubscriptionNetworkService) virtualWans() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId := a.SubscriptionId.Data

	client, err := network.NewVirtualWansClient(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, w := range page.Value {
			mql, err := azureVirtualWanToMql(a.MqlRuntime, w)
			if err != nil {
				return nil, err
			}
			if mql != nil {
				res = append(res, mql)
			}
		}
	}
	return res, nil
}

func azureVirtualWanToMql(runtime *plugin.Runtime, w *network.VirtualWAN) (plugin.Resource, error) {
	if w == nil {
		return nil, nil
	}
	properties, err := convert.JsonToDict(w.Properties)
	if err != nil {
		return nil, err
	}

	args := map[string]*llx.RawData{
		"id":                             llx.StringDataPtr(w.ID),
		"name":                           llx.StringDataPtr(w.Name),
		"location":                       llx.StringDataPtr(w.Location),
		"tags":                           llx.MapData(convert.PtrMapStrToInterface(w.Tags), types.String),
		"type":                           llx.StringDataPtr(w.Type),
		"etag":                           llx.StringDataPtr(w.Etag),
		"properties":                     llx.DictData(properties),
		"allowBranchToBranchTraffic":     llx.BoolDataPtr(nil),
		"allowVnetToVnetTraffic":         llx.BoolDataPtr(nil),
		"disableVpnEncryption":           llx.BoolDataPtr(nil),
		"office365LocalBreakoutCategory": llx.StringDataPtr(nil),
		"virtualWanType":                 llx.StringDataPtr(nil),
		"provisioningState":              llx.StringDataPtr(nil),
	}

	var vpnSiteIds, virtualHubIds []string

	props := w.Properties
	if props != nil {
		args["allowBranchToBranchTraffic"] = llx.BoolDataPtr(props.AllowBranchToBranchTraffic)
		args["allowVnetToVnetTraffic"] = llx.BoolDataPtr(props.AllowVnetToVnetTraffic)
		args["disableVpnEncryption"] = llx.BoolDataPtr(props.DisableVPNEncryption)
		args["virtualWanType"] = llx.StringDataPtr(props.Type)
		if props.Office365LocalBreakoutCategory != nil {
			s := string(*props.Office365LocalBreakoutCategory)
			args["office365LocalBreakoutCategory"] = llx.StringData(s)
		}
		if props.ProvisioningState != nil {
			s := string(*props.ProvisioningState)
			args["provisioningState"] = llx.StringData(s)
		}
		for _, s := range props.VPNSites {
			if s != nil && s.ID != nil {
				vpnSiteIds = append(vpnSiteIds, *s.ID)
			}
		}
		for _, h := range props.VirtualHubs {
			if h != nil && h.ID != nil {
				virtualHubIds = append(virtualHubIds, *h.ID)
			}
		}
	}

	resource, err := CreateResource(runtime, "azure.subscription.networkService.virtualWan", args)
	if err != nil {
		return nil, err
	}
	wan := resource.(*mqlAzureSubscriptionNetworkServiceVirtualWan)
	wan.cacheVpnSiteIds = vpnSiteIds
	wan.cacheVirtualHubIds = virtualHubIds
	return wan, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualWan) virtualHubs() ([]any, error) {
	res := []any{}
	for _, id := range a.cacheVirtualHubIds {
		if id == "" {
			continue
		}
		hub, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.virtualHub", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, hub)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualWan) vpnSites() ([]any, error) {
	res := []any{}
	for _, id := range a.cacheVpnSiteIds {
		if id == "" {
			continue
		}
		site, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.vpnSite", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, site)
	}
	return res, nil
}

func initAzureSubscriptionNetworkServiceVirtualWan(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	name, err := azureId.Component("virtualWans")
	if err != nil {
		return nil, nil, err
	}
	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServiceVirtualWan, id); cached != nil {
		return args, cached, nil
	}

	client, err := network.NewVirtualWansClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), azureId.ResourceGroup, name, nil)
	if err != nil {
		return nil, nil, err
	}
	mql, err := azureVirtualWanToMql(runtime, &resp.VirtualWAN)
	if err != nil {
		return nil, nil, err
	}
	return args, mql, nil
}

// -----------------------------------------------------------------------------
// Virtual Hub
// -----------------------------------------------------------------------------

func (a *mqlAzureSubscriptionNetworkService) virtualHubs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId := a.SubscriptionId.Data

	client, err := network.NewVirtualHubsClient(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, h := range page.Value {
			mql, err := azureVirtualHubToMql(a.MqlRuntime, h)
			if err != nil {
				return nil, err
			}
			if mql != nil {
				res = append(res, mql)
			}
		}
	}
	return res, nil
}

func azureVirtualHubToMql(runtime *plugin.Runtime, h *network.VirtualHub) (plugin.Resource, error) {
	if h == nil {
		return nil, nil
	}
	properties, err := convert.JsonToDict(h.Properties)
	if err != nil {
		return nil, err
	}

	args := map[string]*llx.RawData{
		"id":                         llx.StringDataPtr(h.ID),
		"name":                       llx.StringDataPtr(h.Name),
		"location":                   llx.StringDataPtr(h.Location),
		"tags":                       llx.MapData(convert.PtrMapStrToInterface(h.Tags), types.String),
		"type":                       llx.StringDataPtr(h.Type),
		"etag":                       llx.StringDataPtr(h.Etag),
		"kind":                       llx.StringDataPtr(h.Kind),
		"properties":                 llx.DictData(properties),
		"addressPrefix":              llx.StringDataPtr(nil),
		"sku":                        llx.StringDataPtr(nil),
		"allowBranchToBranchTraffic": llx.BoolDataPtr(nil),
		"preferredRoutingGateway":    llx.StringDataPtr(nil),
		"hubRoutingPreference":       llx.StringDataPtr(nil),
		"virtualRouterAsn":           llx.IntDataDefault[int64](nil, 0),
		"virtualRouterIps":           llx.ArrayData([]any{}, types.String),
		"provisioningState":          llx.StringDataPtr(nil),
		"routingState":               llx.StringDataPtr(nil),
		"securityProviderName":       llx.StringDataPtr(nil),
		"addressPrefixV6":            llx.StringDataPtr(nil),
		"virtualRouterIpsV6":         llx.ArrayData([]any{}, types.String),
	}

	var wanId, fwId *string

	props := h.Properties
	if props != nil {
		args["addressPrefix"] = llx.StringDataPtr(props.AddressPrefix)
		args["sku"] = llx.StringDataPtr(props.SKU)
		args["allowBranchToBranchTraffic"] = llx.BoolDataPtr(props.AllowBranchToBranchTraffic)
		args["virtualRouterAsn"] = llx.IntDataDefault(props.VirtualRouterAsn, 0)
		args["securityProviderName"] = llx.StringDataPtr(props.SecurityProviderName)
		if props.PreferredRoutingGateway != nil {
			s := string(*props.PreferredRoutingGateway)
			args["preferredRoutingGateway"] = llx.StringData(s)
		}
		if props.HubRoutingPreference != nil {
			s := string(*props.HubRoutingPreference)
			args["hubRoutingPreference"] = llx.StringData(s)
		}
		if props.ProvisioningState != nil {
			s := string(*props.ProvisioningState)
			args["provisioningState"] = llx.StringData(s)
		}
		if props.RoutingState != nil {
			s := string(*props.RoutingState)
			args["routingState"] = llx.StringData(s)
		}
		ips := []any{}
		for _, ip := range props.VirtualRouterIPs {
			if ip != nil {
				ips = append(ips, *ip)
			}
		}
		args["virtualRouterIps"] = llx.ArrayData(ips, types.String)

		args["addressPrefixV6"] = llx.StringDataPtr(props.AddressPrefixV6)
		ipsV6 := []any{}
		for _, ip := range props.VirtualRouterIPsV6 {
			if ip != nil {
				ipsV6 = append(ipsV6, *ip)
			}
		}
		args["virtualRouterIpsV6"] = llx.ArrayData(ipsV6, types.String)

		if props.VirtualWan != nil {
			wanId = props.VirtualWan.ID
		}
		if props.AzureFirewall != nil {
			fwId = props.AzureFirewall.ID
		}
	}

	resource, err := CreateResource(runtime, "azure.subscription.networkService.virtualHub", args)
	if err != nil {
		return nil, err
	}
	hub := resource.(*mqlAzureSubscriptionNetworkServiceVirtualHub)
	hub.cacheVirtualWanId = wanId
	hub.cacheAzureFirewallId = fwId
	return hub, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualHub) virtualWan() (*mqlAzureSubscriptionNetworkServiceVirtualWan, error) {
	if a.cacheVirtualWanId == nil || *a.cacheVirtualWanId == "" {
		a.VirtualWan.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.virtualWan", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cacheVirtualWanId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceVirtualWan), nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualHub) azureFirewall() (*mqlAzureSubscriptionNetworkServiceFirewall, error) {
	if a.cacheAzureFirewallId == nil || *a.cacheAzureFirewallId == "" {
		a.AzureFirewall.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.firewall", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cacheAzureFirewallId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceFirewall), nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualHub) routeTables() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	azureId, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := network.NewHubRouteTablesClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListPager(azureId.ResourceGroup, a.Name.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, t := range page.Value {
			if t == nil {
				continue
			}
			labels := []any{}
			routes := []any{}
			associated := []any{}
			propagating := []any{}
			var provState *string
			if t.Properties != nil {
				for _, l := range t.Properties.Labels {
					if l != nil {
						labels = append(labels, *l)
					}
				}
				for _, r := range t.Properties.Routes {
					d, err := convert.JsonToDict(r)
					if err != nil {
						return nil, err
					}
					routes = append(routes, d)
				}
				for _, c := range t.Properties.AssociatedConnections {
					if c != nil {
						associated = append(associated, *c)
					}
				}
				for _, c := range t.Properties.PropagatingConnections {
					if c != nil {
						propagating = append(propagating, *c)
					}
				}
				if t.Properties.ProvisioningState != nil {
					s := string(*t.Properties.ProvisioningState)
					provState = &s
				}
			}
			mql, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.virtualHub.routeTable",
				map[string]*llx.RawData{
					"id":                       llx.StringDataPtr(t.ID),
					"name":                     llx.StringDataPtr(t.Name),
					"type":                     llx.StringDataPtr(t.Type),
					"etag":                     llx.StringDataPtr(t.Etag),
					"labels":                   llx.ArrayData(labels, types.String),
					"routes":                   llx.ArrayData(routes, types.Dict),
					"associatedConnectionIds":  llx.ArrayData(associated, types.String),
					"propagatingConnectionIds": llx.ArrayData(propagating, types.String),
					"provisioningState":        llx.StringDataPtr(provState),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mql)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualHub) vnetConnections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	azureId, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := network.NewHubVirtualNetworkConnectionsClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListPager(azureId.ResourceGroup, a.Name.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, c := range page.Value {
			if c == nil {
				continue
			}
			var enableInternetSecurity *bool
			var routingDict any
			var provState *string
			var remoteId *string
			var enableOnlyIPv6Peering *bool
			if c.Properties != nil {
				enableInternetSecurity = c.Properties.EnableInternetSecurity
				enableOnlyIPv6Peering = c.Properties.EnableOnlyIPv6Peering
				if c.Properties.RoutingConfiguration != nil {
					d, err := convert.JsonToDict(c.Properties.RoutingConfiguration)
					if err != nil {
						return nil, err
					}
					routingDict = d
				}
				if c.Properties.ProvisioningState != nil {
					s := string(*c.Properties.ProvisioningState)
					provState = &s
				}
				if c.Properties.RemoteVirtualNetwork != nil {
					remoteId = c.Properties.RemoteVirtualNetwork.ID
				}
			}
			resource, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.virtualHub.vnetConnection",
				map[string]*llx.RawData{
					"id":                     llx.StringDataPtr(c.ID),
					"name":                   llx.StringDataPtr(c.Name),
					"etag":                   llx.StringDataPtr(c.Etag),
					"enableInternetSecurity": llx.BoolDataPtr(enableInternetSecurity),
					"enableOnlyIPv6Peering":  llx.BoolDataPtr(enableOnlyIPv6Peering),
					"provisioningState":      llx.StringDataPtr(provState),
					"routingConfiguration":   llx.DictData(routingDict),
				})
			if err != nil {
				return nil, err
			}
			vc := resource.(*mqlAzureSubscriptionNetworkServiceVirtualHubVnetConnection)
			vc.cacheRemoteVnetId = remoteId
			res = append(res, vc)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualHubVnetConnection) remoteVirtualNetwork() (*mqlAzureSubscriptionNetworkServiceVirtualNetwork, error) {
	if a.cacheRemoteVnetId == nil || *a.cacheRemoteVnetId == "" {
		a.RemoteVirtualNetwork.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.virtualNetwork", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cacheRemoteVnetId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceVirtualNetwork), nil
}

// init for firewall so virtualHub.azureFirewall() typed ref can resolve, and
// so platform-discovered azure-firewall assets can be queried directly.
func initAzureSubscriptionNetworkServiceFirewall(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromServiceList(runtime, args,
		ResourceAzureSubscriptionNetworkService,
		func(s *mqlAzureSubscriptionNetworkService) *plugin.TValue[[]any] { return s.GetFirewalls() },
		ResourceAzureSubscriptionNetworkServiceFirewall)
}

// initAzureSubscriptionNetworkServiceFirewallPolicy resolves a firewall policy
// by its ARM ID so typed references to it (e.g. from an IP group's
// firewallPolicies backreference) populate fully rather than staying a husk.
func initAzureSubscriptionNetworkServiceFirewallPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	name, err := azureId.Component("firewallPolicies")
	if err != nil {
		return nil, nil, err
	}
	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServiceFirewallPolicy, id); cached != nil {
		return args, cached, nil
	}

	client, err := network.NewFirewallPoliciesClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), azureId.ResourceGroup, name, nil)
	if err != nil {
		return nil, nil, err
	}
	mql, err := azureFirewallPolicyToMql(runtime, resp.FirewallPolicy)
	if err != nil {
		return nil, nil, err
	}
	return args, mql, nil
}

// -----------------------------------------------------------------------------
// ExpressRoute
// -----------------------------------------------------------------------------

// initAzureSubscriptionNetworkServiceExpressRouteCircuit resolves an ExpressRoute
// circuit by its ARM ID so typed references to it (e.g. from an ExpressRoute
// port's circuits) populate fully rather than staying a husk.
func initAzureSubscriptionNetworkServiceExpressRouteCircuit(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	name, err := azureId.Component("expressRouteCircuits")
	if err != nil {
		return nil, nil, err
	}
	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServiceExpressRouteCircuit, id); cached != nil {
		return args, cached, nil
	}

	client, err := network.NewExpressRouteCircuitsClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), azureId.ResourceGroup, name, nil)
	if err != nil {
		return nil, nil, err
	}
	mql, err := azureExpressRouteCircuitToMql(runtime, &resp.ExpressRouteCircuit)
	if err != nil {
		return nil, nil, err
	}
	return args, mql, nil
}

func (a *mqlAzureSubscriptionNetworkService) expressRouteCircuits() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId := a.SubscriptionId.Data

	client, err := network.NewExpressRouteCircuitsClient(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListAllPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, c := range page.Value {
			mql, err := azureExpressRouteCircuitToMql(a.MqlRuntime, c)
			if err != nil {
				return nil, err
			}
			if mql != nil {
				res = append(res, mql)
			}
		}
	}
	return res, nil
}

func azureExpressRouteCircuitToMql(runtime *plugin.Runtime, c *network.ExpressRouteCircuit) (plugin.Resource, error) {
	if c == nil {
		return nil, nil
	}
	properties, err := convert.JsonToDict(c.Properties)
	if err != nil {
		return nil, err
	}

	args := map[string]*llx.RawData{
		"id":                               llx.StringDataPtr(c.ID),
		"name":                             llx.StringDataPtr(c.Name),
		"location":                         llx.StringDataPtr(c.Location),
		"tags":                             llx.MapData(convert.PtrMapStrToInterface(c.Tags), types.String),
		"type":                             llx.StringDataPtr(c.Type),
		"etag":                             llx.StringDataPtr(c.Etag),
		"properties":                       llx.DictData(properties),
		"skuName":                          llx.StringDataPtr(nil),
		"skuTier":                          llx.StringDataPtr(nil),
		"skuFamily":                        llx.StringDataPtr(nil),
		"allowClassicOperations":           llx.BoolDataPtr(nil),
		"globalReachEnabled":               llx.BoolDataPtr(nil),
		"bandwidthInGbps":                  llx.FloatData(0),
		"bandwidthInMbps":                  llx.IntDataDefault[int32](nil, 0),
		"serviceProviderName":              llx.StringDataPtr(nil),
		"peeringLocation":                  llx.StringDataPtr(nil),
		"serviceProviderNotes":             llx.StringDataPtr(nil),
		"circuitProvisioningState":         llx.StringDataPtr(nil),
		"serviceProviderProvisioningState": llx.StringDataPtr(nil),
		"enableDirectPortRateLimit":        llx.BoolDataPtr(nil),
		"expressRoutePortId":               llx.StringDataPtr(nil),
		"authorizationStatus":              llx.StringDataPtr(nil),
		"provisioningState":                llx.StringDataPtr(nil),
		"stag":                             llx.IntDataDefault[int32](nil, 0),
		"resiliencyLevel":                  llx.StringDataPtr(nil),
	}

	if c.SKU != nil {
		args["skuName"] = llx.StringDataPtr(c.SKU.Name)
		if c.SKU.Tier != nil {
			s := string(*c.SKU.Tier)
			args["skuTier"] = llx.StringData(s)
		}
		if c.SKU.Family != nil {
			s := string(*c.SKU.Family)
			args["skuFamily"] = llx.StringData(s)
		}
	}

	props := c.Properties
	if props != nil {
		args["allowClassicOperations"] = llx.BoolDataPtr(props.AllowClassicOperations)
		args["globalReachEnabled"] = llx.BoolDataPtr(props.GlobalReachEnabled)
		args["enableDirectPortRateLimit"] = llx.BoolDataPtr(props.EnableDirectPortRateLimit)
		if props.BandwidthInGbps != nil {
			args["bandwidthInGbps"] = llx.FloatData(float64(*props.BandwidthInGbps))
		}
		args["circuitProvisioningState"] = llx.StringDataPtr(props.CircuitProvisioningState)
		args["authorizationStatus"] = llx.StringDataPtr(props.AuthorizationStatus)
		args["stag"] = llx.IntDataDefault(props.Stag, 0)
		if props.ServiceProviderProvisioningState != nil {
			s := string(*props.ServiceProviderProvisioningState)
			args["serviceProviderProvisioningState"] = llx.StringData(s)
		}
		if props.ProvisioningState != nil {
			s := string(*props.ProvisioningState)
			args["provisioningState"] = llx.StringData(s)
		}
		if props.ResiliencyLevel != nil {
			s := string(*props.ResiliencyLevel)
			args["resiliencyLevel"] = llx.StringData(s)
		}
		if props.ExpressRoutePort != nil {
			args["expressRoutePortId"] = llx.StringDataPtr(props.ExpressRoutePort.ID)
		}
		if sp := props.ServiceProviderProperties; sp != nil {
			args["serviceProviderName"] = llx.StringDataPtr(sp.ServiceProviderName)
			args["peeringLocation"] = llx.StringDataPtr(sp.PeeringLocation)
			args["bandwidthInMbps"] = llx.IntDataDefault(sp.BandwidthInMbps, 0)
		}
		args["serviceProviderNotes"] = llx.StringDataPtr(props.ServiceProviderNotes)
	}

	return CreateResource(runtime, "azure.subscription.networkService.expressRouteCircuit", args)
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteCircuit) peerings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	azureId, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := network.NewExpressRouteCircuitPeeringsClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListPager(azureId.ResourceGroup, a.Name.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, p := range page.Value {
			if p == nil {
				continue
			}
			properties, err := convert.JsonToDict(p.Properties)
			if err != nil {
				return nil, err
			}
			args := map[string]*llx.RawData{
				"id":                         llx.StringDataPtr(p.ID),
				"name":                       llx.StringDataPtr(p.Name),
				"type":                       llx.StringDataPtr(p.Type),
				"etag":                       llx.StringDataPtr(p.Etag),
				"properties":                 llx.DictData(properties),
				"peeringType":                llx.StringDataPtr(nil),
				"state":                      llx.StringDataPtr(nil),
				"azureAsn":                   llx.IntDataDefault[int32](nil, 0),
				"peerAsn":                    llx.IntDataDefault[int64](nil, 0),
				"primaryPeerAddressPrefix":   llx.StringDataPtr(nil),
				"secondaryPeerAddressPrefix": llx.StringDataPtr(nil),
				"primaryAzurePort":           llx.StringDataPtr(nil),
				"secondaryAzurePort":         llx.StringDataPtr(nil),
				"sharedKeySet":               llx.BoolData(false),
				"vlanId":                     llx.IntDataDefault[int32](nil, 0),
				"gatewayManagerEtag":         llx.StringDataPtr(nil),
				"provisioningState":          llx.StringDataPtr(nil),
				"microsoftPeeringConfig":     llx.DictData(nil),
				"ipv6PeeringConfig":          llx.DictData(nil),
			}
			if pp := p.Properties; pp != nil {
				if pp.PeeringType != nil {
					s := string(*pp.PeeringType)
					args["peeringType"] = llx.StringData(s)
				}
				if pp.State != nil {
					s := string(*pp.State)
					args["state"] = llx.StringData(s)
				}
				args["azureAsn"] = llx.IntDataDefault(pp.AzureASN, 0)
				args["peerAsn"] = llx.IntDataDefault(pp.PeerASN, 0)
				args["primaryPeerAddressPrefix"] = llx.StringDataPtr(pp.PrimaryPeerAddressPrefix)
				args["secondaryPeerAddressPrefix"] = llx.StringDataPtr(pp.SecondaryPeerAddressPrefix)
				args["primaryAzurePort"] = llx.StringDataPtr(pp.PrimaryAzurePort)
				args["secondaryAzurePort"] = llx.StringDataPtr(pp.SecondaryAzurePort)
				args["sharedKeySet"] = llx.BoolData(pp.SharedKey != nil && *pp.SharedKey != "")
				args["vlanId"] = llx.IntDataDefault(pp.VlanID, 0)
				args["gatewayManagerEtag"] = llx.StringDataPtr(pp.GatewayManagerEtag)
				if pp.ProvisioningState != nil {
					s := string(*pp.ProvisioningState)
					args["provisioningState"] = llx.StringData(s)
				}
				if pp.MicrosoftPeeringConfig != nil {
					d, err := convert.JsonToDict(pp.MicrosoftPeeringConfig)
					if err != nil {
						return nil, err
					}
					args["microsoftPeeringConfig"] = llx.DictData(d)
				}
				if pp.IPv6PeeringConfig != nil {
					d, err := convert.JsonToDict(pp.IPv6PeeringConfig)
					if err != nil {
						return nil, err
					}
					args["ipv6PeeringConfig"] = llx.DictData(d)
				}
			}
			mql, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.expressRouteCircuit.peering", args)
			if err != nil {
				return nil, err
			}
			res = append(res, mql)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceExpressRouteCircuit) authorizations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	azureId, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := network.NewExpressRouteCircuitAuthorizationsClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListPager(azureId.ResourceGroup, a.Name.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, auth := range page.Value {
			if auth == nil {
				continue
			}
			var useStatus, provState *string
			keySet := false
			if pp := auth.Properties; pp != nil {
				keySet = pp.AuthorizationKey != nil && *pp.AuthorizationKey != ""
				if pp.AuthorizationUseStatus != nil {
					s := string(*pp.AuthorizationUseStatus)
					useStatus = &s
				}
				if pp.ProvisioningState != nil {
					s := string(*pp.ProvisioningState)
					provState = &s
				}
			}
			mql, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.expressRouteCircuit.authorization",
				map[string]*llx.RawData{
					"id":                     llx.StringDataPtr(auth.ID),
					"name":                   llx.StringDataPtr(auth.Name),
					"type":                   llx.StringDataPtr(auth.Type),
					"etag":                   llx.StringDataPtr(auth.Etag),
					"authorizationKeySet":    llx.BoolData(keySet),
					"authorizationUseStatus": llx.StringDataPtr(useStatus),
					"provisioningState":      llx.StringDataPtr(provState),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mql)
		}
	}
	return res, nil
}

// -----------------------------------------------------------------------------
// Network Watcher: packetCaptures + connectionMonitors
// -----------------------------------------------------------------------------

func (a *mqlAzureSubscriptionNetworkServiceWatcher) packetCaptures() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	azureId, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := network.NewPacketCapturesClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListPager(azureId.ResourceGroup, a.Name.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, pc := range page.Value {
			if pc == nil {
				continue
			}
			properties, err := convert.JsonToDict(pc.Properties)
			if err != nil {
				return nil, err
			}
			args := map[string]*llx.RawData{
				"id":                      llx.StringDataPtr(pc.ID),
				"name":                    llx.StringDataPtr(pc.Name),
				"etag":                    llx.StringDataPtr(pc.Etag),
				"properties":              llx.DictData(properties),
				"target":                  llx.StringDataPtr(nil),
				"targetType":              llx.StringDataPtr(nil),
				"bytesToCapturePerPacket": llx.IntDataDefault[int64](nil, 0),
				"timeLimitInSeconds":      llx.IntDataDefault[int32](nil, 0),
				"totalBytesPerSession":    llx.IntDataDefault[int64](nil, 0),
				"continuousCapture":       llx.BoolDataPtr(nil),
				"filters":                 llx.ArrayData([]any{}, types.Dict),
				"storageLocation":         llx.DictData(nil),
				"provisioningState":       llx.StringDataPtr(nil),
			}
			if pp := pc.Properties; pp != nil {
				args["target"] = llx.StringDataPtr(pp.Target)
				args["bytesToCapturePerPacket"] = llx.IntDataDefault(pp.BytesToCapturePerPacket, 0)
				args["timeLimitInSeconds"] = llx.IntDataDefault(pp.TimeLimitInSeconds, 0)
				args["totalBytesPerSession"] = llx.IntDataDefault(pp.TotalBytesPerSession, 0)
				args["continuousCapture"] = llx.BoolDataPtr(pp.ContinuousCapture)
				if pp.TargetType != nil {
					s := string(*pp.TargetType)
					args["targetType"] = llx.StringData(s)
				}
				if pp.ProvisioningState != nil {
					s := string(*pp.ProvisioningState)
					args["provisioningState"] = llx.StringData(s)
				}
				if pp.StorageLocation != nil {
					d, err := convert.JsonToDict(pp.StorageLocation)
					if err != nil {
						return nil, err
					}
					args["storageLocation"] = llx.DictData(d)
				}
				filters := []any{}
				for _, f := range pp.Filters {
					d, err := convert.JsonToDict(f)
					if err != nil {
						return nil, err
					}
					filters = append(filters, d)
				}
				args["filters"] = llx.ArrayData(filters, types.Dict)
			}
			mql, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.watcher.packetCapture", args)
			if err != nil {
				return nil, err
			}
			res = append(res, mql)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceWatcher) connectionMonitors() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	azureId, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := network.NewConnectionMonitorsClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListPager(azureId.ResourceGroup, a.Name.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, cm := range page.Value {
			if cm == nil {
				continue
			}
			properties, err := convert.JsonToDict(cm.Properties)
			if err != nil {
				return nil, err
			}
			args := map[string]*llx.RawData{
				"id":                          llx.StringDataPtr(cm.ID),
				"name":                        llx.StringDataPtr(cm.Name),
				"location":                    llx.StringDataPtr(cm.Location),
				"tags":                        llx.MapData(convert.PtrMapStrToInterface(cm.Tags), types.String),
				"type":                        llx.StringDataPtr(cm.Type),
				"etag":                        llx.StringDataPtr(cm.Etag),
				"properties":                  llx.DictData(properties),
				"autoStart":                   llx.BoolDataPtr(nil),
				"monitoringIntervalInSeconds": llx.IntDataDefault[int32](nil, 0),
				"notes":                       llx.StringDataPtr(nil),
				"connectionMonitorType":       llx.StringDataPtr(nil),
				"monitoringStatus":            llx.StringDataPtr(nil),
				"provisioningState":           llx.StringDataPtr(nil),
				"endpoints":                   llx.ArrayData([]any{}, types.Dict),
				"testConfigurations":          llx.ArrayData([]any{}, types.Dict),
				"testGroups":                  llx.ArrayData([]any{}, types.Dict),
				"outputs":                     llx.ArrayData([]any{}, types.Dict),
			}
			if pp := cm.Properties; pp != nil {
				args["autoStart"] = llx.BoolDataPtr(pp.AutoStart)
				args["monitoringIntervalInSeconds"] = llx.IntDataDefault(pp.MonitoringIntervalInSeconds, 0)
				args["notes"] = llx.StringDataPtr(pp.Notes)
				args["monitoringStatus"] = llx.StringDataPtr(pp.MonitoringStatus)
				if pp.ConnectionMonitorType != nil {
					s := string(*pp.ConnectionMonitorType)
					args["connectionMonitorType"] = llx.StringData(s)
				}
				if pp.ProvisioningState != nil {
					s := string(*pp.ProvisioningState)
					args["provisioningState"] = llx.StringData(s)
				}
				endpoints := []any{}
				for _, e := range pp.Endpoints {
					d, err := convert.JsonToDict(e)
					if err != nil {
						return nil, err
					}
					endpoints = append(endpoints, d)
				}
				args["endpoints"] = llx.ArrayData(endpoints, types.Dict)

				configs := []any{}
				for _, t := range pp.TestConfigurations {
					d, err := convert.JsonToDict(t)
					if err != nil {
						return nil, err
					}
					configs = append(configs, d)
				}
				args["testConfigurations"] = llx.ArrayData(configs, types.Dict)

				groups := []any{}
				for _, g := range pp.TestGroups {
					d, err := convert.JsonToDict(g)
					if err != nil {
						return nil, err
					}
					groups = append(groups, d)
				}
				args["testGroups"] = llx.ArrayData(groups, types.Dict)

				outputs := []any{}
				for _, o := range pp.Outputs {
					d, err := convert.JsonToDict(o)
					if err != nil {
						return nil, err
					}
					outputs = append(outputs, d)
				}
				args["outputs"] = llx.ArrayData(outputs, types.Dict)
			}
			mql, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.watcher.connectionMonitor", args)
			if err != nil {
				return nil, err
			}
			res = append(res, mql)
		}
	}
	return res, nil
}

// -----------------------------------------------------------------------------
// VPN Site
// -----------------------------------------------------------------------------

func (a *mqlAzureSubscriptionNetworkService) vpnSites() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId := a.SubscriptionId.Data

	client, err := network.NewVPNSitesClient(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, s := range page.Value {
			mql, err := azureVpnSiteToMql(a.MqlRuntime, s)
			if err != nil {
				return nil, err
			}
			if mql != nil {
				res = append(res, mql)
			}
		}
	}
	return res, nil
}

func azureVpnSiteToMql(runtime *plugin.Runtime, s *network.VPNSite) (plugin.Resource, error) {
	if s == nil {
		return nil, nil
	}
	properties, err := convert.JsonToDict(s.Properties)
	if err != nil {
		return nil, err
	}

	args := map[string]*llx.RawData{
		"id":                llx.StringDataPtr(s.ID),
		"name":              llx.StringDataPtr(s.Name),
		"location":          llx.StringDataPtr(s.Location),
		"tags":              llx.MapData(convert.PtrMapStrToInterface(s.Tags), types.String),
		"type":              llx.StringDataPtr(s.Type),
		"etag":              llx.StringDataPtr(s.Etag),
		"properties":        llx.DictData(properties),
		"ipAddress":         llx.StringDataPtr(nil),
		"addressPrefixes":   llx.ArrayData([]any{}, types.String),
		"isSecuritySite":    llx.BoolDataPtr(nil),
		"siteKeySet":        llx.BoolData(false),
		"deviceVendor":      llx.StringDataPtr(nil),
		"deviceModel":       llx.StringDataPtr(nil),
		"linkSpeedInMbps":   llx.IntDataDefault[int32](nil, 0),
		"bgpAsn":            llx.IntDataDefault[int64](nil, 0),
		"bgpPeeringAddress": llx.StringDataPtr(nil),
		"bgpPeerWeight":     llx.IntDataDefault[int32](nil, 0),
		"o365Policy":        llx.DictData(nil),
		"vpnSiteLinks":      llx.ArrayData([]any{}, types.Dict),
		"provisioningState": llx.StringDataPtr(nil),
	}

	var wanId *string

	if pp := s.Properties; pp != nil {
		args["ipAddress"] = llx.StringDataPtr(pp.IPAddress)
		args["isSecuritySite"] = llx.BoolDataPtr(pp.IsSecuritySite)
		args["siteKeySet"] = llx.BoolData(pp.SiteKey != nil && *pp.SiteKey != "")
		if pp.ProvisioningState != nil {
			s := string(*pp.ProvisioningState)
			args["provisioningState"] = llx.StringData(s)
		}
		if as := pp.AddressSpace; as != nil {
			prefixes := []any{}
			for _, p := range as.AddressPrefixes {
				if p != nil {
					prefixes = append(prefixes, *p)
				}
			}
			args["addressPrefixes"] = llx.ArrayData(prefixes, types.String)
		}
		if d := pp.DeviceProperties; d != nil {
			args["deviceVendor"] = llx.StringDataPtr(d.DeviceVendor)
			args["deviceModel"] = llx.StringDataPtr(d.DeviceModel)
			args["linkSpeedInMbps"] = llx.IntDataDefault(d.LinkSpeedInMbps, 0)
		}
		if b := pp.BgpProperties; b != nil {
			args["bgpAsn"] = llx.IntDataDefault(b.Asn, 0)
			args["bgpPeeringAddress"] = llx.StringDataPtr(b.BgpPeeringAddress)
			args["bgpPeerWeight"] = llx.IntDataDefault(b.PeerWeight, 0)
		}
		if pp.O365Policy != nil {
			d, err := convert.JsonToDict(pp.O365Policy)
			if err != nil {
				return nil, err
			}
			args["o365Policy"] = llx.DictData(d)
		}
		links := []any{}
		for _, l := range pp.VPNSiteLinks {
			d, err := convert.JsonToDict(l)
			if err != nil {
				return nil, err
			}
			links = append(links, d)
		}
		args["vpnSiteLinks"] = llx.ArrayData(links, types.Dict)
		if pp.VirtualWan != nil {
			wanId = pp.VirtualWan.ID
		}
	}

	resource, err := CreateResource(runtime, "azure.subscription.networkService.vpnSite", args)
	if err != nil {
		return nil, err
	}
	site := resource.(*mqlAzureSubscriptionNetworkServiceVpnSite)
	site.cacheVirtualWanId = wanId
	return site, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVpnSite) virtualWan() (*mqlAzureSubscriptionNetworkServiceVirtualWan, error) {
	if a.cacheVirtualWanId == nil || *a.cacheVirtualWanId == "" {
		a.VirtualWan.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.virtualWan", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cacheVirtualWanId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceVirtualWan), nil
}

func initAzureSubscriptionNetworkServiceVirtualHub(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	name, err := azureId.Component("virtualHubs")
	if err != nil {
		return nil, nil, err
	}
	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServiceVirtualHub, id); cached != nil {
		return args, cached, nil
	}

	client, err := network.NewVirtualHubsClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), azureId.ResourceGroup, name, nil)
	if err != nil {
		return nil, nil, err
	}
	mql, err := azureVirtualHubToMql(runtime, &resp.VirtualHub)
	if err != nil {
		return nil, nil, err
	}
	return args, mql, nil
}

func initAzureSubscriptionNetworkServiceVpnSite(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	name, err := azureId.Component("vpnSites")
	if err != nil {
		return nil, nil, err
	}
	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServiceVpnSite, id); cached != nil {
		return args, cached, nil
	}

	client, err := network.NewVPNSitesClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), azureId.ResourceGroup, name, nil)
	if err != nil {
		return nil, nil, err
	}
	mql, err := azureVpnSiteToMql(runtime, &resp.VPNSite)
	if err != nil {
		return nil, nil, err
	}
	return args, mql, nil
}
