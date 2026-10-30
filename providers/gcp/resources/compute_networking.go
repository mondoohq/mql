// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

type mqlGcpProjectComputeServiceInterconnectAttachmentInternal struct {
	cacheInterconnectUrl string
	cacheRegionUrl       string
	cacheRouterUrl       string
}

type mqlGcpProjectComputeServiceNetworkEndpointGroupInternal struct {
	cacheNetworkUrl    string
	cacheRegionUrl     string
	cacheSubnetworkUrl string
	cacheZoneUrl       string
}

type mqlGcpProjectComputeServicePacketMirroringInternal struct {
	cacheRegionUrl string
}

type mqlGcpProjectComputeServiceServiceAttachmentInternal struct {
	cacheRegionUrl string
}

type mqlGcpProjectComputeServiceTargetSslProxyInternal struct {
	cacheServiceUrl   string
	cacheSslPolicyUrl string
}

type mqlGcpProjectComputeServiceTargetTcpProxyInternal struct {
	cacheRegionUrl  string
	cacheServiceUrl string
}

type mqlGcpProjectComputeServiceVpnTunnelInternal struct {
	cachePeerExternalGateway string
	cachePeerGcpGateway      string
	cacheRegionUrl           string
	cacheRouterUrl           string
	cacheVpnGatewayUrl       string
}

// ---------------------------------------------------------------
// Cross-reference helper functions
// ---------------------------------------------------------------

func getRouterByUrl(routerUrl string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceRouter, error) {
	if routerUrl == "" {
		return nil, nil
	}
	// URL format: projects/{project}/regions/{region}/routers/{name}
	params := trimComputeURL(routerUrl)
	parts := strings.Split(params, "/")
	if len(parts) < 6 {
		return nil, nil
	}
	projectId := parts[1]
	targetName := parts[5]

	res, err := CreateResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	svc := res.(*mqlGcpProjectComputeService)
	routers := svc.GetRouters()
	if routers.Error != nil {
		return nil, routers.Error
	}
	// Router resource does not store selfLink or regionUrl, so we match by
	// name within the project. Router names are unique per-region; same-name
	// routers across regions are rare in practice.
	for _, r := range routers.Data {
		router := r.(*mqlGcpProjectComputeServiceRouter)
		if router.GetName().Data == targetName {
			return router, nil
		}
	}
	return nil, nil
}

func getVpnGatewayByUrl(gwUrl string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceVpnGateway, error) {
	if gwUrl == "" {
		return nil, nil
	}
	// URL format: projects/{project}/regions/{region}/vpnGateways/{name}
	params := trimComputeURL(gwUrl)
	parts := strings.Split(params, "/")
	if len(parts) < 6 {
		return nil, nil
	}
	projectId := parts[1]
	targetRegion := parts[3]
	targetName := parts[5]

	res, err := CreateResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	svc := res.(*mqlGcpProjectComputeService)
	gateways := svc.GetVpnGateways()
	if gateways.Error != nil {
		return nil, gateways.Error
	}
	// VPN gateways are region-scoped and have regionUrl; match by name + region
	for _, g := range gateways.Data {
		gw := g.(*mqlGcpProjectComputeServiceVpnGateway)
		if gw.GetName().Data == targetName && strings.HasSuffix(gw.cacheRegionUrl, "/"+targetRegion) {
			return gw, nil
		}
	}
	return nil, nil
}

func getExternalVpnGatewayByUrl(gwUrl string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceExternalVpnGateway, error) {
	if gwUrl == "" {
		return nil, nil
	}
	params := trimComputeURL(gwUrl)
	parts := strings.Split(params, "/")
	if len(parts) < 2 {
		return nil, nil
	}
	projectId := parts[1]

	res, err := CreateResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	svc := res.(*mqlGcpProjectComputeService)
	gateways := svc.GetExternalVpnGateways()
	if gateways.Error != nil {
		return nil, gateways.Error
	}
	// External VPN gateways are global and have selfLink; match by selfLink
	for _, g := range gateways.Data {
		gw := g.(*mqlGcpProjectComputeServiceExternalVpnGateway)
		if gw.SelfLink.Data == gwUrl {
			return gw, nil
		}
	}
	return nil, nil
}

func getInterconnectByUrl(icUrl string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceInterconnect, error) {
	if icUrl == "" {
		return nil, nil
	}
	params := trimComputeURL(icUrl)
	parts := strings.Split(params, "/")
	if len(parts) < 2 {
		return nil, nil
	}
	projectId := parts[1]

	res, err := CreateResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	svc := res.(*mqlGcpProjectComputeService)
	interconnects := svc.GetInterconnects()
	if interconnects.Error != nil {
		return nil, interconnects.Error
	}
	for _, i := range interconnects.Data {
		ic := i.(*mqlGcpProjectComputeServiceInterconnect)
		if ic.SelfLink.Data == icUrl {
			return ic, nil
		}
	}
	return nil, nil
}

func getSecurityPolicyByUrl(policyUrl string, runtime *plugin.Runtime) (*mqlGcpProjectComputeServiceSecurityPolicy, error) {
	if policyUrl == "" {
		return nil, nil
	}
	params := trimComputeURL(policyUrl)
	parts := strings.Split(params, "/")
	if len(parts) < 2 {
		return nil, nil
	}
	projectId := parts[1]

	res, err := CreateResource(runtime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}
	svc := res.(*mqlGcpProjectComputeService)
	policies := svc.GetSecurityPolicies()
	if policies.Error != nil {
		return nil, policies.Error
	}
	for _, p := range policies.Data {
		policy := p.(*mqlGcpProjectComputeServiceSecurityPolicy)
		if policy.SelfLink.Data == policyUrl {
			return policy, nil
		}
	}
	return nil, nil
}

// ---------------------------------------------------------------
// Cross-reference methods for existing resources
// ---------------------------------------------------------------

// vpnTunnel cross-references

func (g *mqlGcpProjectComputeServiceVpnTunnel) router() (*mqlGcpProjectComputeServiceRouter, error) {
	routerUrl := g.cacheRouterUrl
	if routerUrl == "" {
		g.Router.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	router, err := getRouterByUrl(routerUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if router == nil {
		g.Router.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return router, nil
}

func (g *mqlGcpProjectComputeServiceVpnTunnel) vpnGateway() (*mqlGcpProjectComputeServiceVpnGateway, error) {
	gwUrl := g.cacheVpnGatewayUrl
	if gwUrl == "" {
		g.VpnGateway.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	gw, err := getVpnGatewayByUrl(gwUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if gw == nil {
		g.VpnGateway.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return gw, nil
}

func (g *mqlGcpProjectComputeServiceVpnTunnel) peerExternalVpnGateway() (*mqlGcpProjectComputeServiceExternalVpnGateway, error) {
	gwUrl := g.cachePeerExternalGateway
	if gwUrl == "" {
		g.PeerExternalVpnGateway.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	gw, err := getExternalVpnGatewayByUrl(gwUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if gw == nil {
		g.PeerExternalVpnGateway.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return gw, nil
}

func (g *mqlGcpProjectComputeServiceVpnTunnel) peerGcpVpnGateway() (*mqlGcpProjectComputeServiceVpnGateway, error) {
	gwUrl := g.cachePeerGcpGateway
	if gwUrl == "" {
		g.PeerGcpVpnGateway.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	gw, err := getVpnGatewayByUrl(gwUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if gw == nil {
		g.PeerGcpVpnGateway.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return gw, nil
}

// interconnectAttachment cross-references

func (g *mqlGcpProjectComputeServiceInterconnectAttachment) interconnect() (*mqlGcpProjectComputeServiceInterconnect, error) {
	icUrl := g.cacheInterconnectUrl
	if icUrl == "" {
		g.Interconnect.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	ic, err := getInterconnectByUrl(icUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if ic == nil {
		g.Interconnect.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return ic, nil
}

func (g *mqlGcpProjectComputeServiceInterconnectAttachment) router() (*mqlGcpProjectComputeServiceRouter, error) {
	routerUrl := g.cacheRouterUrl
	if routerUrl == "" {
		g.Router.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	router, err := getRouterByUrl(routerUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if router == nil {
		g.Router.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return router, nil
}

// backendService cross-references

func (g *mqlGcpProjectComputeServiceBackendService) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	networkUrl := g.cacheNetworkUrl
	if networkUrl == "" {
		g.Network.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	network, err := getNetworkByUrl(networkUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if network == nil {
		g.Network.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return network, nil
}

func (g *mqlGcpProjectComputeServiceBackendService) securityPolicy() (*mqlGcpProjectComputeServiceSecurityPolicy, error) {
	policyUrl := g.cacheSecurityPolicyUrl
	if policyUrl == "" {
		g.SecurityPolicy.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	policy, err := getSecurityPolicyByUrl(policyUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		g.SecurityPolicy.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return policy, nil
}

// ---------------------------------------------------------------
// Routes
// ---------------------------------------------------------------

func (g *mqlGcpProjectComputeServiceRoute) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeServiceRoute) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	networkUrl := g.cacheNetworkUrl
	if networkUrl == "" {
		g.Network.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	network, err := getNetworkByUrl(networkUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if network == nil {
		g.Network.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return network, nil
}

func (g *mqlGcpProjectComputeService) routes() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.Routes.List(projectId)
	if err := req.Pages(ctx, func(page *compute.RouteList) error {
		for _, r := range page.Items {
			asPaths := make([]any, 0, len(r.AsPaths))
			for _, ap := range r.AsPaths {
				d, err := convert.JsonToDict(ap)
				if err != nil {
					return err
				}
				asPaths = append(asPaths, d)
			}
			warnings := make([]any, 0, len(r.Warnings))
			for _, w := range r.Warnings {
				d, err := convert.JsonToDict(w)
				if err != nil {
					return err
				}
				warnings = append(warnings, d)
			}

			mqlRoute, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.route", map[string]*llx.RawData{
				"id":               llx.StringData(fmt.Sprintf("%d", r.Id)),
				"name":             llx.StringData(r.Name),
				"description":      llx.StringData(r.Description),
				"destRange":        llx.StringData(r.DestRange),
				"priority":         llx.IntData(r.Priority),
				"nextHopGateway":   llx.StringData(r.NextHopGateway),
				"nextHopInstance":  llx.StringData(r.NextHopInstance),
				"nextHopIp":        llx.StringData(r.NextHopIp),
				"nextHopVpnTunnel": llx.StringData(r.NextHopVpnTunnel),
				"nextHopNetwork":   llx.StringData(r.NextHopNetwork),
				"nextHopPeering":   llx.StringData(r.NextHopPeering),
				"nextHopIlb":       llx.StringData(r.NextHopIlb),
				"nextHopHub":       llx.StringData(r.NextHopHub),
				"routeType":        llx.StringData(r.RouteType),
				"routeStatus":      llx.StringData(r.RouteStatus),
				"tags":             llx.ArrayData(convert.SliceAnyToInterface(r.Tags), types.String),
				"asPaths":          llx.ArrayData(asPaths, types.Dict),
				"warnings":         llx.ArrayData(warnings, types.Dict),
				"created":          llx.TimeDataPtr(parseTime(r.CreationTimestamp)),
				"selfLink":         llx.StringData(r.SelfLink),
			})
			if err != nil {
				return err
			}
			mqlRef := mqlRoute.(*mqlGcpProjectComputeServiceRoute)
			mqlRef.cacheNetworkUrl = r.Network
			res = append(res, mqlRoute)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

// ---------------------------------------------------------------
// Service Attachments
// ---------------------------------------------------------------

func (g *mqlGcpProjectComputeServiceServiceAttachment) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeService) serviceAttachments() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.ServiceAttachments.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.ServiceAttachmentAggregatedList) error {
		for _, scopedList := range page.Items {
			for _, sa := range scopedList.ServiceAttachments {
				connectedEndpoints := make([]any, 0, len(sa.ConnectedEndpoints))
				for _, ep := range sa.ConnectedEndpoints {
					d, err := convert.JsonToDict(ep)
					if err != nil {
						return err
					}
					connectedEndpoints = append(connectedEndpoints, d)
				}
				consumerAcceptLists := make([]any, 0, len(sa.ConsumerAcceptLists))
				for _, cal := range sa.ConsumerAcceptLists {
					d, err := convert.JsonToDict(cal)
					if err != nil {
						return err
					}
					consumerAcceptLists = append(consumerAcceptLists, d)
				}

				mqlSA, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.serviceAttachment", map[string]*llx.RawData{
					"id":                     llx.StringData(fmt.Sprintf("%d", sa.Id)),
					"name":                   llx.StringData(sa.Name),
					"description":            llx.StringData(sa.Description),
					"connectionPreference":   llx.StringData(sa.ConnectionPreference),
					"connectedEndpoints":     llx.ArrayData(connectedEndpoints, types.Dict),
					"consumerAcceptLists":    llx.ArrayData(consumerAcceptLists, types.Dict),
					"consumerRejectLists":    llx.ArrayData(convert.SliceAnyToInterface(sa.ConsumerRejectLists), types.String),
					"enableProxyProtocol":    llx.BoolData(sa.EnableProxyProtocol),
					"domainNames":            llx.ArrayData(convert.SliceAnyToInterface(sa.DomainNames), types.String),
					"natSubnets":             llx.ArrayData(convert.SliceAnyToInterface(sa.NatSubnets), types.String),
					"producerForwardingRule": llx.StringData(sa.ProducerForwardingRule),
					"targetService":          llx.StringData(sa.TargetService),
					"reconcileConnections":   llx.BoolData(sa.ReconcileConnections),
					"selfLink":               llx.StringData(sa.SelfLink),
					"fingerprint":            llx.StringData(sa.Fingerprint),
					"created":                llx.TimeDataPtr(parseTime(sa.CreationTimestamp)),
				})
				if err != nil {
					return err
				}
				mqlRef := mqlSA.(*mqlGcpProjectComputeServiceServiceAttachment)
				mqlRef.cacheRegionUrl = sa.Region
				res = append(res, mqlSA)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

// ---------------------------------------------------------------
// Network Endpoint Groups
// ---------------------------------------------------------------

func (g *mqlGcpProjectComputeServiceNetworkEndpointGroup) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeServiceNetworkEndpointGroup) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	networkUrl := g.cacheNetworkUrl
	if networkUrl == "" {
		g.Network.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	network, err := getNetworkByUrl(networkUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if network == nil {
		g.Network.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return network, nil
}

func (g *mqlGcpProjectComputeServiceNetworkEndpointGroup) subnetwork() (*mqlGcpProjectComputeServiceSubnetwork, error) {
	subnetUrl := g.cacheSubnetworkUrl
	if subnetUrl == "" {
		g.Subnetwork.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	subnet, err := getSubnetworkByUrl(subnetUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if subnet == nil {
		g.Subnetwork.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return subnet, nil
}

func (g *mqlGcpProjectComputeService) networkEndpointGroups() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.NetworkEndpointGroups.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.NetworkEndpointGroupAggregatedList) error {
		for _, scopedList := range page.Items {
			for _, neg := range scopedList.NetworkEndpointGroups {
				cloudRun, err := convert.JsonToDict(neg.CloudRun)
				if err != nil {
					return err
				}
				appEngine, err := convert.JsonToDict(neg.AppEngine)
				if err != nil {
					return err
				}
				cloudFunction, err := convert.JsonToDict(neg.CloudFunction)
				if err != nil {
					return err
				}
				pscData, err := convert.JsonToDict(neg.PscData)
				if err != nil {
					return err
				}

				var annotations map[string]any
				if neg.Annotations != nil {
					annotations = convert.MapToInterfaceMap(neg.Annotations)
				}

				mqlNEG, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.networkEndpointGroup", map[string]*llx.RawData{
					"id":                  llx.StringData(fmt.Sprintf("%d", neg.Id)),
					"name":                llx.StringData(neg.Name),
					"description":         llx.StringData(neg.Description),
					"networkEndpointType": llx.StringData(neg.NetworkEndpointType),
					"defaultPort":         llx.IntData(neg.DefaultPort),
					"size":                llx.IntData(neg.Size),
					"cloudRun":            llx.DictData(cloudRun),
					"appEngine":           llx.DictData(appEngine),
					"cloudFunction":       llx.DictData(cloudFunction),
					"pscTargetService":    llx.StringData(neg.PscTargetService),
					"pscData":             llx.DictData(pscData),
					"annotations":         llx.MapData(annotations, types.String),
					"selfLink":            llx.StringData(neg.SelfLink),
					"created":             llx.TimeDataPtr(parseTime(neg.CreationTimestamp)),
				})
				if err != nil {
					return err
				}
				mqlRef := mqlNEG.(*mqlGcpProjectComputeServiceNetworkEndpointGroup)
				mqlRef.cacheNetworkUrl = neg.Network
				mqlRef.cacheSubnetworkUrl = neg.Subnetwork
				mqlRef.cacheZoneUrl = neg.Zone
				mqlRef.cacheRegionUrl = neg.Region
				res = append(res, mqlNEG)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

// ---------------------------------------------------------------
// Interconnects
// ---------------------------------------------------------------

func (g *mqlGcpProjectComputeServiceInterconnect) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeService) interconnects() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.Interconnects.List(projectId)
	if err := req.Pages(ctx, func(page *compute.InterconnectList) error {
		for _, ic := range page.Items {
			circuitInfos := make([]any, 0, len(ic.CircuitInfos))
			for _, ci := range ic.CircuitInfos {
				d, err := convert.JsonToDict(ci)
				if err != nil {
					return err
				}
				circuitInfos = append(circuitInfos, d)
			}
			expectedOutages := make([]any, 0, len(ic.ExpectedOutages))
			for _, eo := range ic.ExpectedOutages {
				d, err := convert.JsonToDict(eo)
				if err != nil {
					return err
				}
				expectedOutages = append(expectedOutages, d)
			}

			mqlIC, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.interconnect", map[string]*llx.RawData{
				"id":                         llx.StringData(fmt.Sprintf("%d", ic.Id)),
				"name":                       llx.StringData(ic.Name),
				"description":                llx.StringData(ic.Description),
				"adminEnabled":               llx.BoolData(ic.AdminEnabled),
				"interconnectType":           llx.StringData(ic.InterconnectType),
				"linkType":                   llx.StringData(ic.LinkType),
				"requestedLinkCount":         llx.IntData(ic.RequestedLinkCount),
				"provisionedLinkCount":       llx.IntData(ic.ProvisionedLinkCount),
				"customerName":               llx.StringData(ic.CustomerName),
				"operationalStatus":          llx.StringData(ic.OperationalStatus),
				"state":                      llx.StringData(ic.State),
				"googleIpAddress":            llx.StringData(ic.GoogleIpAddress),
				"peerIpAddress":              llx.StringData(ic.PeerIpAddress),
				"googleReferenceId":          llx.StringData(ic.GoogleReferenceId),
				"nocContactEmail":            llx.StringData(ic.NocContactEmail),
				"location":                   llx.StringData(ic.Location),
				"remoteLocation":             llx.StringData(ic.RemoteLocation),
				"labels":                     llx.MapData(convert.MapToInterfaceMap(ic.Labels), types.String),
				"availableFeatures":          llx.ArrayData(convert.SliceAnyToInterface(ic.AvailableFeatures), types.String),
				"requestedFeatures":          llx.ArrayData(convert.SliceAnyToInterface(ic.RequestedFeatures), types.String),
				"interconnectAttachmentUrls": llx.ArrayData(convert.SliceAnyToInterface(ic.InterconnectAttachments), types.String),
				"circuitInfos":               llx.ArrayData(circuitInfos, types.Dict),
				"expectedOutages":            llx.ArrayData(expectedOutages, types.Dict),
				"satisfiesPzs":               llx.BoolData(ic.SatisfiesPzs),
				"selfLink":                   llx.StringData(ic.SelfLink),
				"created":                    llx.TimeDataPtr(parseTime(ic.CreationTimestamp)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlIC)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

// ---------------------------------------------------------------
// Interconnect Attachments
// ---------------------------------------------------------------

func (g *mqlGcpProjectComputeServiceInterconnectAttachment) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeService) interconnectAttachments() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.InterconnectAttachments.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.InterconnectAttachmentAggregatedList) error {
		for _, scopedList := range page.Items {
			for _, ia := range scopedList.InterconnectAttachments {
				partnerMetadata, err := convert.JsonToDict(ia.PartnerMetadata)
				if err != nil {
					return err
				}
				privateInfo, err := convert.JsonToDict(ia.PrivateInterconnectInfo)
				if err != nil {
					return err
				}

				mqlIA, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.interconnectAttachment", map[string]*llx.RawData{
					"id":                        llx.StringData(fmt.Sprintf("%d", ia.Id)),
					"name":                      llx.StringData(ia.Name),
					"description":               llx.StringData(ia.Description),
					"adminEnabled":              llx.BoolData(ia.AdminEnabled),
					"bandwidth":                 llx.StringData(ia.Bandwidth),
					"type":                      llx.StringData(ia.Type),
					"state":                     llx.StringData(ia.State),
					"edgeAvailabilityDomain":    llx.StringData(ia.EdgeAvailabilityDomain),
					"cloudRouterIpAddress":      llx.StringData(ia.CloudRouterIpAddress),
					"customerRouterIpAddress":   llx.StringData(ia.CustomerRouterIpAddress),
					"cloudRouterIpv6Address":    llx.StringData(ia.CloudRouterIpv6Address),
					"customerRouterIpv6Address": llx.StringData(ia.CustomerRouterIpv6Address),
					"stackType":                 llx.StringData(ia.StackType),
					"encryption":                llx.StringData(ia.Encryption),
					"vlanTag8021q":              llx.IntData(ia.VlanTag8021q),
					"partnerMetadata":           llx.DictData(partnerMetadata),
					"privateInterconnectInfo":   llx.DictData(privateInfo),
					"selfLink":                  llx.StringData(ia.SelfLink),
					"dataplaneVersion":          llx.IntData(ia.DataplaneVersion),
					"labels":                    llx.MapData(convert.MapToInterfaceMap(ia.Labels), types.String),
					"created":                   llx.TimeDataPtr(parseTime(ia.CreationTimestamp)),
				})
				if err != nil {
					return err
				}
				mqlRef := mqlIA.(*mqlGcpProjectComputeServiceInterconnectAttachment)
				mqlRef.cacheInterconnectUrl = ia.Interconnect
				mqlRef.cacheRouterUrl = ia.Router
				mqlRef.cacheRegionUrl = ia.Region
				res = append(res, mqlIA)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

// ---------------------------------------------------------------
// External VPN Gateways
// ---------------------------------------------------------------

func (g *mqlGcpProjectComputeServiceExternalVpnGateway) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeService) externalVpnGateways() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.ExternalVpnGateways.List(projectId)
	if err := req.Pages(ctx, func(page *compute.ExternalVpnGatewayList) error {
		for _, gw := range page.Items {
			interfaces := make([]any, 0, len(gw.Interfaces))
			for _, iface := range gw.Interfaces {
				d, err := convert.JsonToDict(iface)
				if err != nil {
					return err
				}
				interfaces = append(interfaces, d)
			}

			var gwId string
			if gw.Id != nil {
				gwId = fmt.Sprintf("%d", *gw.Id)
			}

			mqlGw, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.externalVpnGateway", map[string]*llx.RawData{
				"id":             llx.StringData(gwId),
				"name":           llx.StringData(gw.Name),
				"description":    llx.StringData(gw.Description),
				"redundancyType": llx.StringData(gw.RedundancyType),
				"labels":         llx.MapData(convert.MapToInterfaceMap(gw.Labels), types.String),
				"interfaces":     llx.ArrayData(interfaces, types.Dict),
				"selfLink":       llx.StringData(gw.SelfLink),
				"created":        llx.TimeDataPtr(parseTime(gw.CreationTimestamp)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlGw)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

// ---------------------------------------------------------------
// Target TCP Proxies
// ---------------------------------------------------------------

func (g *mqlGcpProjectComputeServiceTargetTcpProxy) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeService) targetTcpProxies() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.TargetTcpProxies.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.TargetTcpProxyAggregatedList) error {
		for _, scopedList := range page.Items {
			for _, tp := range scopedList.TargetTcpProxies {
				mqlTP, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.targetTcpProxy", map[string]*llx.RawData{
					"id":          llx.StringData(fmt.Sprintf("%d", tp.Id)),
					"name":        llx.StringData(tp.Name),
					"description": llx.StringData(tp.Description),
					"proxyHeader": llx.StringData(tp.ProxyHeader),
					"proxyBind":   llx.BoolData(tp.ProxyBind),
					"selfLink":    llx.StringData(tp.SelfLink),
					"created":     llx.TimeDataPtr(parseTime(tp.CreationTimestamp)),
				})
				if err != nil {
					return err
				}
				mqlRef := mqlTP.(*mqlGcpProjectComputeServiceTargetTcpProxy)
				mqlRef.cacheServiceUrl = tp.Service
				mqlRef.cacheRegionUrl = tp.Region
				res = append(res, mqlTP)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

// ---------------------------------------------------------------
// Target SSL Proxies
// ---------------------------------------------------------------

func (g *mqlGcpProjectComputeServiceTargetSslProxy) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeServiceTargetSslProxy) sslPolicy() (*mqlGcpProjectComputeServiceSslPolicy, error) {
	sslPolicyUrl := g.cacheSslPolicyUrl
	if sslPolicyUrl == "" {
		g.SslPolicy.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	policy, err := getSslPolicyByUrl(sslPolicyUrl, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		g.SslPolicy.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return policy, nil
}

func (g *mqlGcpProjectComputeService) targetSslProxies() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.TargetSslProxies.List(projectId)
	if err := req.Pages(ctx, func(page *compute.TargetSslProxyList) error {
		for _, sp := range page.Items {
			mqlSP, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.targetSslProxy", map[string]*llx.RawData{
				"id":                 llx.StringData(fmt.Sprintf("%d", sp.Id)),
				"name":               llx.StringData(sp.Name),
				"description":        llx.StringData(sp.Description),
				"proxyHeader":        llx.StringData(sp.ProxyHeader),
				"sslCertificateUrls": llx.ArrayData(convert.SliceAnyToInterface(sp.SslCertificates), types.String),
				"certificateMap":     llx.StringData(sp.CertificateMap),
				"selfLink":           llx.StringData(sp.SelfLink),
				"created":            llx.TimeDataPtr(parseTime(sp.CreationTimestamp)),
			})
			if err != nil {
				return err
			}
			mqlRef := mqlSP.(*mqlGcpProjectComputeServiceTargetSslProxy)
			mqlRef.cacheServiceUrl = sp.Service
			mqlRef.cacheSslPolicyUrl = sp.SslPolicy
			res = append(res, mqlSP)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

// ---------------------------------------------------------------
// Packet Mirrorings
// ---------------------------------------------------------------

func (g *mqlGcpProjectComputeServicePacketMirroring) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeService) packetMirrorings() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.PacketMirrorings.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.PacketMirroringAggregatedList) error {
		for _, scopedList := range page.Items {
			for _, pm := range scopedList.PacketMirrorings {
				networkDict, err := convert.JsonToDict(pm.Network)
				if err != nil {
					return err
				}
				collectorIlb, err := convert.JsonToDict(pm.CollectorIlb)
				if err != nil {
					return err
				}
				mirroredResources, err := convert.JsonToDict(pm.MirroredResources)
				if err != nil {
					return err
				}
				filter, err := convert.JsonToDict(pm.Filter)
				if err != nil {
					return err
				}

				mqlPM, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.packetMirroring", map[string]*llx.RawData{
					"id":                llx.StringData(fmt.Sprintf("%d", pm.Id)),
					"name":              llx.StringData(pm.Name),
					"description":       llx.StringData(pm.Description),
					"enable":            llx.StringData(pm.Enable),
					"priority":          llx.IntData(pm.Priority),
					"network":           llx.DictData(networkDict),
					"collectorIlb":      llx.DictData(collectorIlb),
					"mirroredResources": llx.DictData(mirroredResources),
					"filter":            llx.DictData(filter),
					"selfLink":          llx.StringData(pm.SelfLink),
					"created":           llx.TimeDataPtr(parseTime(pm.CreationTimestamp)),
				})
				if err != nil {
					return err
				}
				mqlRef := mqlPM.(*mqlGcpProjectComputeServicePacketMirroring)
				mqlRef.cacheRegionUrl = pm.Region
				res = append(res, mqlPM)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

// ---------------------------------------------------------------
// Backend Buckets
// ---------------------------------------------------------------

func (g *mqlGcpProjectComputeServiceBackendBucket) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeService) backendBuckets() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.BackendBuckets.List(projectId)
	if err := req.Pages(ctx, func(page *compute.BackendBucketList) error {
		for _, bb := range page.Items {
			cdnPolicy, err := convert.JsonToDict(bb.CdnPolicy)
			if err != nil {
				return err
			}

			mqlBB, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.backendBucket", map[string]*llx.RawData{
				"id":                    llx.StringData(fmt.Sprintf("%d", bb.Id)),
				"name":                  llx.StringData(bb.Name),
				"description":           llx.StringData(bb.Description),
				"bucketName":            llx.StringData(bb.BucketName),
				"enableCdn":             llx.BoolData(bb.EnableCdn),
				"cdnPolicy":             llx.DictData(cdnPolicy),
				"compressionMode":       llx.StringData(bb.CompressionMode),
				"customResponseHeaders": llx.ArrayData(convert.SliceAnyToInterface(bb.CustomResponseHeaders), types.String),
				"edgeSecurityPolicy":    llx.StringData(bb.EdgeSecurityPolicy),
				"selfLink":              llx.StringData(bb.SelfLink),
				"created":               llx.TimeDataPtr(parseTime(bb.CreationTimestamp)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlBB)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

// ---------------------------------------------------------------
// Target Pools
// ---------------------------------------------------------------

func (g *mqlGcpProjectComputeServiceTargetPool) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeService) targetPools() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.TargetPools.AggregatedList(projectId)
	if err := req.Pages(ctx, func(page *compute.TargetPoolAggregatedList) error {
		for _, scopedList := range page.Items {
			for _, tp := range scopedList.TargetPools {
				mqlTP, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.targetPool", map[string]*llx.RawData{
					"id":              llx.StringData(fmt.Sprintf("%d", tp.Id)),
					"name":            llx.StringData(tp.Name),
					"description":     llx.StringData(tp.Description),
					"sessionAffinity": llx.StringData(tp.SessionAffinity),
					"failoverRatio":   llx.FloatData(tp.FailoverRatio),
					"healthCheckUrls": llx.ArrayData(convert.SliceAnyToInterface(tp.HealthChecks), types.String),
					"instanceUrls":    llx.ArrayData(convert.SliceAnyToInterface(tp.Instances), types.String),
					"selfLink":        llx.StringData(tp.SelfLink),
					"created":         llx.TimeDataPtr(parseTime(tp.CreationTimestamp)),
				})
				if err != nil {
					return err
				}
				mqlRef := mqlTP.(*mqlGcpProjectComputeServiceTargetPool)
				mqlRef.cacheBackupPoolUrl = tp.BackupPool
				mqlRef.cacheSecurityPolicyUrl = tp.SecurityPolicy
				mqlRef.cacheRegionUrl = tp.Region
				res = append(res, mqlTP)
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

// ---------------------------------------------------------------
// Public Advertised Prefixes
// ---------------------------------------------------------------

func (g *mqlGcpProjectComputeServicePublicAdvertisedPrefix) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectComputeService) publicAdvertisedPrefixes() ([]any, error) {
	enabled, err := g.serviceEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	client, err := conn.Client(cloudresourcemanager.CloudPlatformReadOnlyScope, iam.CloudPlatformScope, compute.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	req := computeSvc.PublicAdvertisedPrefixes.List(projectId)
	if err := req.Pages(ctx, func(page *compute.PublicAdvertisedPrefixList) error {
		for _, pap := range page.Items {
			publicDelegatedPrefixes := make([]any, 0, len(pap.PublicDelegatedPrefixs))
			for _, pdp := range pap.PublicDelegatedPrefixs {
				d, err := convert.JsonToDict(pdp)
				if err != nil {
					return err
				}
				publicDelegatedPrefixes = append(publicDelegatedPrefixes, d)
			}

			mqlPAP, err := CreateResource(g.MqlRuntime, "gcp.project.computeService.publicAdvertisedPrefix", map[string]*llx.RawData{
				"id":                      llx.StringData(fmt.Sprintf("%d", pap.Id)),
				"name":                    llx.StringData(pap.Name),
				"description":             llx.StringData(pap.Description),
				"ipCidrRange":             llx.StringData(pap.IpCidrRange),
				"status":                  llx.StringData(pap.Status),
				"dnsVerificationIp":       llx.StringData(pap.DnsVerificationIp),
				"byoipApiVersion":         llx.StringData(pap.ByoipApiVersion),
				"pdpScope":                llx.StringData(pap.PdpScope),
				"publicDelegatedPrefixes": llx.ArrayData(publicDelegatedPrefixes, types.Dict),
				"selfLink":                llx.StringData(pap.SelfLink),
				"fingerprint":             llx.StringData(pap.Fingerprint),
				"created":                 llx.TimeDataPtr(parseTime(pap.CreationTimestamp)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlPAP)
		}
		return nil
	}); err != nil {
		// Public Advertised Prefixes may not be available in all projects
		log.Warn().Str("project", projectId).Err(err).Msg("could not list public advertised prefixes")
		return nil, nil
	}
	return res, nil
}
