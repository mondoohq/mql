// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	dataplex "google.golang.org/api/dataplex/v1"
	"google.golang.org/api/option"
)

type mqlGcpProjectDataplexServiceLakeInternal struct {
	cacheServiceAccount string
}

func (g *mqlGcpProjectDataplexService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("%s/gcp.project.dataplexService", g.ProjectId.Data), nil
}

func (g *mqlGcpProject) dataplex() (*mqlGcpProjectDataplexService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	serviceEnabled, err := g.isServiceEnabled(service_dataplex)
	if err != nil {
		return nil, err
	}
	if !serviceEnabled {
		log.Debug().Str("service", service_dataplex).Msg("gcp service is not enabled, skipping")
	}

	res, err := CreateResource(g.MqlRuntime, "gcp.project.dataplexService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
		"enabled":   llx.BoolData(serviceEnabled),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectDataplexService), nil
}

// Direct construction (e.g. `gcp.project.dataplexService.lakes`) bypasses
// gcp.project.dataplex(), leaving projectId and enabled unset. Delegate to
// the parent project accessor so both are populated.
func initGcpProjectDataplexService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["projectId"]; ok {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	proj, err := NewResource(runtime, "gcp.project", map[string]*llx.RawData{
		"id": llx.StringData(conn.ResourceID()),
	})
	if err != nil {
		return nil, nil, err
	}
	svc, err := proj.(*mqlGcpProject).dataplex()
	if err != nil {
		return nil, nil, err
	}
	return nil, svc, nil
}

func (g *mqlGcpProjectDataplexService) lakes() ([]any, error) {
	if g.Enabled.Error != nil {
		return nil, g.Enabled.Error
	}
	if !g.Enabled.Data {
		return []any{}, nil
	}
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(dataplex.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	dataplexSvc, err := dataplex.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	// The "-" location wildcard lists lakes across every location in a single
	// aggregated call, so there's no need to enumerate locations and fan out.
	parent := fmt.Sprintf("projects/%s/locations/-", projectId)
	var mqlLakes []any
	err = dataplexSvc.Projects.Locations.Lakes.List(parent).Pages(ctx, func(resp *dataplex.GoogleCloudDataplexV1ListLakesResponse) error {
		for _, lake := range resp.Lakes {
			metastoreService := ""
			if lake.Metastore != nil {
				metastoreService = lake.Metastore.Service
			}

			var activeAssets, securityPolicyApplyingAssets int64
			if lake.AssetStatus != nil {
				activeAssets = lake.AssetStatus.ActiveAssets
				securityPolicyApplyingAssets = lake.AssetStatus.SecurityPolicyApplyingAssets
			}

			mqlLake, err := CreateResource(g.MqlRuntime, "gcp.project.dataplexService.lake", map[string]*llx.RawData{
				"__id":                         llx.StringData(lake.Name),
				"id":                           llx.StringData(lake.Name),
				"projectId":                    llx.StringData(projectId),
				"location":                     llx.StringData(dataplexLocation(lake.Name)),
				"name":                         llx.StringData(serviceName(lake.Name)),
				"displayName":                  llx.StringData(lake.DisplayName),
				"description":                  llx.StringData(lake.Description),
				"uid":                          llx.StringData(lake.Uid),
				"state":                        llx.StringData(lake.State),
				"created":                      llx.TimeDataPtr(parseTime(lake.CreateTime)),
				"updated":                      llx.TimeDataPtr(parseTime(lake.UpdateTime)),
				"labels":                       llx.MapData(convert.MapToInterfaceMap(lake.Labels), types.String),
				"metastoreService":             llx.StringData(metastoreService),
				"activeAssets":                 llx.IntData(activeAssets),
				"securityPolicyApplyingAssets": llx.IntData(securityPolicyApplyingAssets),
			})
			if err != nil {
				log.Error().Err(err).Send()
				continue
			}
			mqlRef := mqlLake.(*mqlGcpProjectDataplexServiceLake)
			mqlRef.cacheServiceAccount = lake.ServiceAccount
			mqlLakes = append(mqlLakes, mqlLake)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return mqlLakes, nil
}

// dataplexLocation extracts the location segment from a Dataplex resource name
// of the form projects/{project}/locations/{location}/lakes/{lake}/...
func dataplexLocation(name string) string {
	parts := strings.Split(name, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "locations" {
			return parts[i+1]
		}
	}
	return ""
}

func (g *mqlGcpProjectDataplexServiceLake) serviceAccountRef() (*mqlGcpProjectIamServiceServiceAccount, error) {
	sa, err := resolveServiceAccountRef(g.MqlRuntime, g.cacheServiceAccount, g.ProjectId.Data)
	if err != nil {
		return nil, err
	}
	if sa == nil {
		g.ServiceAccountRef.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return sa, nil
}

func (g *mqlGcpProjectDataplexServiceLake) zones() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	lakeName := g.Id.Data

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.Location.Error != nil {
		return nil, g.Location.Error
	}
	location := g.Location.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(dataplex.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	dataplexSvc, err := dataplex.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var mqlZones []any
	err = dataplexSvc.Projects.Locations.Lakes.Zones.List(lakeName).Pages(ctx, func(resp *dataplex.GoogleCloudDataplexV1ListZonesResponse) error {
		for _, zone := range resp.Zones {
			locationType := ""
			if zone.ResourceSpec != nil {
				locationType = zone.ResourceSpec.LocationType
			}

			discoveryEnabled := false
			discoverySchedule := ""
			var includePatterns, excludePatterns []any
			if zone.DiscoverySpec != nil {
				discoveryEnabled = zone.DiscoverySpec.Enabled
				discoverySchedule = zone.DiscoverySpec.Schedule
				includePatterns = convert.SliceAnyToInterface(zone.DiscoverySpec.IncludePatterns)
				excludePatterns = convert.SliceAnyToInterface(zone.DiscoverySpec.ExcludePatterns)
			}

			mqlZone, err := CreateResource(g.MqlRuntime, "gcp.project.dataplexService.lake.zone", map[string]*llx.RawData{
				"__id":                     llx.StringData(zone.Name),
				"id":                       llx.StringData(zone.Name),
				"projectId":                llx.StringData(projectId),
				"location":                 llx.StringData(location),
				"name":                     llx.StringData(serviceName(zone.Name)),
				"displayName":              llx.StringData(zone.DisplayName),
				"description":              llx.StringData(zone.Description),
				"uid":                      llx.StringData(zone.Uid),
				"state":                    llx.StringData(zone.State),
				"type":                     llx.StringData(zone.Type),
				"resourceLocationType":     llx.StringData(locationType),
				"created":                  llx.TimeDataPtr(parseTime(zone.CreateTime)),
				"updated":                  llx.TimeDataPtr(parseTime(zone.UpdateTime)),
				"labels":                   llx.MapData(convert.MapToInterfaceMap(zone.Labels), types.String),
				"discoveryEnabled":         llx.BoolData(discoveryEnabled),
				"discoverySchedule":        llx.StringData(discoverySchedule),
				"discoveryIncludePatterns": llx.ArrayData(includePatterns, types.String),
				"discoveryExcludePatterns": llx.ArrayData(excludePatterns, types.String),
			})
			if err != nil {
				log.Error().Err(err).Send()
				continue
			}
			mqlZones = append(mqlZones, mqlZone)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return mqlZones, nil
}

func (g *mqlGcpProjectDataplexServiceLakeZone) assets() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	zoneName := g.Id.Data

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.Location.Error != nil {
		return nil, g.Location.Error
	}
	location := g.Location.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(dataplex.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	dataplexSvc, err := dataplex.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var mqlAssets []any
	err = dataplexSvc.Projects.Locations.Lakes.Zones.Assets.List(zoneName).Pages(ctx, func(resp *dataplex.GoogleCloudDataplexV1ListAssetsResponse) error {
		for _, asset := range resp.Assets {
			resourceType := ""
			resourceName := ""
			readAccessMode := ""
			if asset.ResourceSpec != nil {
				resourceType = asset.ResourceSpec.Type
				resourceName = asset.ResourceSpec.Name
				readAccessMode = asset.ResourceSpec.ReadAccessMode
			}

			securityStatusState := ""
			if asset.SecurityStatus != nil {
				securityStatusState = asset.SecurityStatus.State
			}

			discoveryEnabled := false
			discoverySchedule := ""
			if asset.DiscoverySpec != nil {
				discoveryEnabled = asset.DiscoverySpec.Enabled
				discoverySchedule = asset.DiscoverySpec.Schedule
			}

			mqlAsset, err := CreateResource(g.MqlRuntime, "gcp.project.dataplexService.lake.zone.asset", map[string]*llx.RawData{
				"__id":                llx.StringData(asset.Name),
				"id":                  llx.StringData(asset.Name),
				"projectId":           llx.StringData(projectId),
				"location":            llx.StringData(location),
				"name":                llx.StringData(serviceName(asset.Name)),
				"displayName":         llx.StringData(asset.DisplayName),
				"description":         llx.StringData(asset.Description),
				"uid":                 llx.StringData(asset.Uid),
				"state":               llx.StringData(asset.State),
				"created":             llx.TimeDataPtr(parseTime(asset.CreateTime)),
				"updated":             llx.TimeDataPtr(parseTime(asset.UpdateTime)),
				"labels":              llx.MapData(convert.MapToInterfaceMap(asset.Labels), types.String),
				"resourceType":        llx.StringData(resourceType),
				"resourceName":        llx.StringData(resourceName),
				"readAccessMode":      llx.StringData(readAccessMode),
				"securityStatusState": llx.StringData(securityStatusState),
				"discoveryEnabled":    llx.BoolData(discoveryEnabled),
				"discoverySchedule":   llx.StringData(discoverySchedule),
			})
			if err != nil {
				log.Error().Err(err).Send()
				continue
			}
			mqlAssets = append(mqlAssets, mqlAsset)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return mqlAssets, nil
}
