// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	networkconnectivity "cloud.google.com/go/networkconnectivity/apiv1"
	"cloud.google.com/go/networkconnectivity/apiv1/networkconnectivitypb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	googleoauth "golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type mqlGcpProjectNetworkConnectivityServiceInternal struct {
	serviceGate
}

type mqlGcpProjectNetworkConnectivityServiceHubInternal struct {
	// routingVpcUris are the network self-links from the hub's routing VPCs,
	// kept so routingVpcNetworks() resolves them without re-parsing the dict.
	routingVpcUris []string
}

type mqlGcpProjectNetworkConnectivityServiceSpokeInternal struct {
	// projectId is the project the spoke was listed under, needed to reach the
	// hub list when resolving hub().
	projectId string
}

func (g *mqlGcpProject) networkConnectivity() (*mqlGcpProjectNetworkConnectivityService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.networkConnectivityService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_networkconnectivity)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectNetworkConnectivityService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_networkconnectivity).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

func initGcpProjectNetworkConnectivityService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	if args == nil {
		args = make(map[string]*llx.RawData)
	}
	args["projectId"] = llx.StringData(conn.ResourceID())
	return args, nil, nil
}

func (g *mqlGcpProjectNetworkConnectivityService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("%s/gcp.project.networkConnectivityService", g.ProjectId.Data), nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectNetworkConnectivityService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_networkconnectivity)
}

// networkConnectivityCredentials returns credentials scoped for the Network
// Connectivity API. Only the credentials are shared, not the client: the
// permissions extractor tracks client variables per function, so a helper
// returning the client would hide the constructor and drop the permissions from
// the manifest.
func (g *mqlGcpProjectNetworkConnectivityService) networkConnectivityCredentials() (*googleoauth.Credentials, error) {
	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	return conn.Credentials(networkconnectivity.DefaultAuthScopes()...)
}

func (g *mqlGcpProjectNetworkConnectivityServiceHub) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectNetworkConnectivityServiceSpoke) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

// hubs lists the project's connectivity hubs. Hubs are global resources.
func (g *mqlGcpProjectNetworkConnectivityService) hubs() ([]any, error) {
	enabled, err := g.isEnabled()
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

	creds, err := g.networkConnectivityCredentials()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := networkconnectivity.NewHubClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListHubs(ctx, &networkconnectivitypb.ListHubsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/global", projectId),
	})

	res := []any{}
	for {
		hub, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				// break rather than discard: an error partway through pagination
				// should not throw away the hubs the API already returned.
				log.Warn().Err(err).Str("project", projectId).Msg("could not list all Network Connectivity hubs")
				break
			}
			return nil, err
		}

		routingVpcs, err := protoToDictSlice(hub.GetRoutingVpcs())
		if err != nil {
			return nil, err
		}
		routingVpcUris := make([]string, 0, len(hub.GetRoutingVpcs()))
		for _, v := range hub.GetRoutingVpcs() {
			if uri := v.GetUri(); uri != "" {
				routingVpcUris = append(routingVpcUris, uri)
			}
		}
		spokeSummary, err := protoToDict(hub.GetSpokeSummary())
		if err != nil {
			return nil, err
		}

		mqlHub, err := CreateResource(g.MqlRuntime, "gcp.project.networkConnectivityService.hub", map[string]*llx.RawData{
			"name":         llx.StringData(hub.GetName()),
			"description":  llx.StringData(hub.GetDescription()),
			"uniqueId":     llx.StringData(hub.GetUniqueId()),
			"state":        llx.StringData(hub.GetState().String()),
			"policyMode":   llx.StringData(hub.GetPolicyMode().String()),
			"routingVpcs":  llx.ArrayData(routingVpcs, types.Dict),
			"routeTables":  llx.ArrayData(convert.SliceAnyToInterface(hub.GetRouteTables()), types.String),
			"spokeSummary": llx.DictData(spokeSummary),
			"labels":       llx.MapData(convert.MapToInterfaceMap(hub.GetLabels()), types.String),
			"createTime":   llx.TimeDataPtr(timestampAsTimePtr(hub.GetCreateTime())),
			"updateTime":   llx.TimeDataPtr(timestampAsTimePtr(hub.GetUpdateTime())),
		})
		if err != nil {
			return nil, err
		}
		mqlHub.(*mqlGcpProjectNetworkConnectivityServiceHub).routingVpcUris = routingVpcUris
		res = append(res, mqlHub)
	}

	return res, nil
}

// routingVpcNetworks resolves the networks the hub routes traffic through, so a
// review can follow the fabric into the subnets and firewall rules of the
// networks actually carrying it.
func (g *mqlGcpProjectNetworkConnectivityServiceHub) routingVpcNetworks() ([]any, error) {
	res := make([]any, 0, len(g.routingVpcUris))
	for _, uri := range g.routingVpcUris {
		net, err := getNetworkByUrl(uri, g.MqlRuntime)
		if err != nil {
			// A routing VPC can live in another project the caller cannot read.
			// Skip it rather than failing the whole list; the raw uri stays
			// available in routingVpcs.
			log.Debug().Err(err).Str("network", uri).Msg("could not resolve hub routing VPC network")
			continue
		}
		if net == nil {
			continue
		}
		res = append(res, net)
	}
	return res, nil
}

// spokes lists the project's spokes. The "-" location wildcard collects spokes
// from every region in one call, which matters because a spoke lives in the
// region of the resource it attaches, not in global.
func (g *mqlGcpProjectNetworkConnectivityService) spokes() ([]any, error) {
	enabled, err := g.isEnabled()
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

	creds, err := g.networkConnectivityCredentials()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := networkconnectivity.NewHubClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListSpokes(ctx, &networkconnectivitypb.ListSpokesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	res := []any{}
	for {
		spoke, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				// break rather than discard: keep the spokes already returned.
				log.Warn().Err(err).Str("project", projectId).Msg("could not list all Network Connectivity spokes")
				break
			}
			return nil, err
		}

		reasons, err := protoToDictSlice(spoke.GetReasons())
		if err != nil {
			return nil, err
		}
		linkedVpcNetwork, err := protoToDict(spoke.GetLinkedVpcNetwork())
		if err != nil {
			return nil, err
		}
		linkedVpnTunnels, err := protoToDict(spoke.GetLinkedVpnTunnels())
		if err != nil {
			return nil, err
		}
		linkedInterconnectAttachments, err := protoToDict(spoke.GetLinkedInterconnectAttachments())
		if err != nil {
			return nil, err
		}
		linkedRouterApplianceInstances, err := protoToDict(spoke.GetLinkedRouterApplianceInstances())
		if err != nil {
			return nil, err
		}

		mqlSpoke, err := CreateResource(g.MqlRuntime, "gcp.project.networkConnectivityService.spoke", map[string]*llx.RawData{
			"name":                           llx.StringData(spoke.GetName()),
			"description":                    llx.StringData(spoke.GetDescription()),
			"hubName":                        llx.StringData(spoke.GetHub()),
			"group":                          llx.StringData(spoke.GetGroup()),
			"spokeType":                      llx.StringData(spoke.GetSpokeType().String()),
			"state":                          llx.StringData(spoke.GetState().String()),
			"reasons":                        llx.ArrayData(reasons, types.Dict),
			"linkedVpcNetwork":               llx.DictData(linkedVpcNetwork),
			"linkedVpnTunnels":               llx.DictData(linkedVpnTunnels),
			"linkedInterconnectAttachments":  llx.DictData(linkedInterconnectAttachments),
			"linkedRouterApplianceInstances": llx.DictData(linkedRouterApplianceInstances),
			"uniqueId":                       llx.StringData(spoke.GetUniqueId()),
			"labels":                         llx.MapData(convert.MapToInterfaceMap(spoke.GetLabels()), types.String),
			"createTime":                     llx.TimeDataPtr(timestampAsTimePtr(spoke.GetCreateTime())),
			"updateTime":                     llx.TimeDataPtr(timestampAsTimePtr(spoke.GetUpdateTime())),
		})
		if err != nil {
			return nil, err
		}
		mqlSpoke.(*mqlGcpProjectNetworkConnectivityServiceSpoke).projectId = projectId
		res = append(res, mqlSpoke)
	}

	return res, nil
}

// hub resolves the hub the spoke is attached to, so a spoke leads to the other
// spokes it has been made mutually reachable with.
//
// Resolution goes through the project's hub list rather than a per-spoke Get:
// the list is fetched once and cached on the service resource, so N spokes cost
// one call rather than N.
func (g *mqlGcpProjectNetworkConnectivityServiceSpoke) hub() (*mqlGcpProjectNetworkConnectivityServiceHub, error) {
	if g.HubName.Error != nil {
		return nil, g.HubName.Error
	}
	hubName := g.HubName.Data
	if hubName == "" || g.projectId == "" {
		g.Hub.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	svc, err := NewResource(g.MqlRuntime, "gcp.project.networkConnectivityService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.projectId),
	})
	if err != nil {
		return nil, err
	}

	hubs := svc.(*mqlGcpProjectNetworkConnectivityService).GetHubs()
	if hubs.Error != nil {
		return nil, hubs.Error
	}
	for _, raw := range hubs.Data {
		h, ok := raw.(*mqlGcpProjectNetworkConnectivityServiceHub)
		if !ok || h == nil {
			continue
		}
		if h.Name.Error == nil && h.Name.Data == hubName {
			return h, nil
		}
	}

	// A spoke can be attached to a hub in another project, which the
	// project-scoped list does not contain.
	g.Hub.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
