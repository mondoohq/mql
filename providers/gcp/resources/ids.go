// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	ids "cloud.google.com/go/ids/apiv1"
	"cloud.google.com/go/ids/apiv1/idspb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type mqlGcpProjectIdsServiceEndpointInternal struct {
	cacheNetworkUrl string
}

type mqlGcpProjectIdsServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProject) ids() (*mqlGcpProjectIdsService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.idsService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_ids)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectIdsService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_ids).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

func initGcpProjectIdsService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	projectId := conn.ResourceID()
	args["projectId"] = llx.StringData(projectId)

	return args, nil, nil
}

func (g *mqlGcpProjectIdsService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("%s/gcp.project.idsService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectIdsServiceEndpoint) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectIdsService) endpoints() ([]any, error) {
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

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(ids.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := ids.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListEndpoints(ctx, &idspb.ListEndpointsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		ep, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Cloud IDS endpoints")
				break
			}
			return nil, err
		}

		mqlEp, err := CreateResource(g.MqlRuntime, "gcp.project.idsService.endpoint", map[string]*llx.RawData{
			"name":                   llx.StringData(ep.Name),
			"description":            llx.StringData(ep.Description),
			"endpointForwardingRule": llx.StringData(ep.EndpointForwardingRule),
			"endpointIp":             llx.StringData(ep.EndpointIp),
			"severity":               llx.StringData(ep.Severity.String()),
			"state":                  llx.StringData(ep.State.String()),
			"trafficLogs":            llx.BoolData(ep.TrafficLogs),
			"labels":                 llx.MapData(convert.MapToInterfaceMap(ep.Labels), types.String),
			"created":                llx.TimeDataPtr(timestampAsTimePtr(ep.CreateTime)),
			"updated":                llx.TimeDataPtr(timestampAsTimePtr(ep.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		mqlRef := mqlEp.(*mqlGcpProjectIdsServiceEndpoint)
		mqlRef.cacheNetworkUrl = ep.Network
		res = append(res, mqlEp)
	}

	return res, nil
}

func (g *mqlGcpProjectIdsServiceEndpoint) network() (*mqlGcpProjectComputeServiceNetwork, error) {
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

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectIdsService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_ids)
}
