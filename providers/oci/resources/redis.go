// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/redis"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciRedis) id() (string, error) {
	return "oci.redis", nil
}

func (o *mqlOciRedis) clusters() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci redis cluster with region %s", region)

			svc, err := conn.RedisClusterClient(region)
			if err != nil {
				return nil, err
			}

			clusters, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]redis.RedisClusterSummary, *string, error) {
				response, err := svc.ListRedisClusters(ctx, redis.ListRedisClustersRequest{
					CompartmentId: common.String(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(clusters))
			for i := range clusters {
				c := clusters[i]

				if conn.Filters.IsFilteredOutByTags(c.FreeformTags, c.DefinedTags) {
					continue
				}

				var created, updated *time.Time
				if c.TimeCreated != nil {
					created = &c.TimeCreated.Time
				}
				if c.TimeUpdated != nil {
					updated = &c.TimeUpdated.Time
				}

				var nodeMemory float64
				if c.NodeMemoryInGBs != nil {
					nodeMemory = float64(*c.NodeMemoryInGBs)
				}

				mqlCluster, err := createOciResourceInCompartment(o.MqlRuntime, "oci.redis.cluster", stringValue(c.CompartmentId), map[string]*llx.RawData{
					"id":                         llx.StringDataPtr(c.Id),
					"name":                       llx.StringDataPtr(c.DisplayName),
					"softwareVersion":            llx.StringData(string(c.SoftwareVersion)),
					"clusterMode":                llx.StringData(string(c.ClusterMode)),
					"clusterRole":                llx.StringDataPtr(redisClusterRole(c.ClusterRole)),
					"nodeCount":                  llx.IntDataPtr(c.NodeCount),
					"nodeMemoryInGBs":            llx.FloatData(nodeMemory),
					"shardCount":                 llx.IntDataPtr(c.ShardCount),
					"primaryFqdn":                llx.StringDataPtr(c.PrimaryFqdn),
					"primaryEndpointIpAddress":   llx.StringDataPtr(c.PrimaryEndpointIpAddress),
					"replicasFqdn":               llx.StringDataPtr(c.ReplicasFqdn),
					"replicasEndpointIpAddress":  llx.StringDataPtr(c.ReplicasEndpointIpAddress),
					"discoveryFqdn":              llx.StringDataPtr(c.DiscoveryFqdn),
					"discoveryEndpointIpAddress": llx.StringDataPtr(c.DiscoveryEndpointIpAddress),
					"state":                      llx.StringData(string(c.LifecycleState)),
					"created":                    llx.TimeDataPtr(created),
					"timeUpdated":                llx.TimeDataPtr(updated),
					"freeformTags":               llx.MapData(strMapToAny(c.FreeformTags), types.String),
					"definedTags":                llx.MapData(definedTagsToAny(c.DefinedTags), types.Any),
					"systemTags":                 llx.MapData(definedTagsToAny(c.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlClusterTyped := mqlCluster.(*mqlOciRedisCluster)
				mqlClusterTyped.cacheSubnetID = stringValue(c.SubnetId)
				mqlClusterTyped.cacheNsgIDs = c.NsgIds
				mqlClusterTyped.cacheRegion = region
				mqlClusterTyped.cachePrimaryClusterID = stringValue(c.PrimaryClusterId)
				res = append(res, mqlClusterTyped)
			}

			return res, nil
		})
}

type mqlOciRedisClusterInternal struct {
	ociCompartmentRef
	cacheSubnetID         string
	cacheNsgIDs           []string
	cacheRegion           string
	cachePrimaryClusterID string
}

// redisClusterRole maps the cross-region replication role to a nullable
// string. Clusters created before the role was reported come back with an
// empty role, which has to read as null rather than as a fourth role value.
func redisClusterRole(role redis.RedisClusterClusterRoleEnum) *string {
	if role == "" {
		return nil
	}
	s := string(role)
	return &s
}

func initOciRedisCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idVal := ociArgString(args, "id")
	if idVal == "" {
		conn := runtime.Connection.(*connection.OciConnection)
		if conn.Conf == nil || conn.Conf.PlatformId == "" {
			return args, nil, nil
		}
		parsed, ok := parseOciObjectPlatformID(conn.Conf.PlatformId)
		if !ok || parsed.service != "redis" || parsed.objectType != "cluster" {
			return args, nil, nil
		}
		idVal = parsed.id
	}

	obj, err := CreateResource(runtime, "oci.redis", nil)
	if err != nil {
		return nil, nil, err
	}
	svc := obj.(*mqlOciRedis)

	rawClusters := svc.GetClusters()
	if rawClusters.Error != nil {
		return nil, nil, rawClusters.Error
	}

	for _, raw := range rawClusters.Data {
		c := raw.(*mqlOciRedisCluster)
		if c.Id.Data == idVal {
			return args, c, nil
		}
	}

	return nil, nil, errors.New("oci.redis.cluster not found: " + idVal)
}

func (o *mqlOciRedisCluster) id() (string, error) {
	return "oci.redis.cluster/" + o.Id.Data, nil
}

func (o *mqlOciRedisCluster) primaryCluster() (*mqlOciRedisCluster, error) {
	if o.cachePrimaryClusterID == "" {
		o.PrimaryCluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlCluster, err := NewResource(o.MqlRuntime, "oci.redis.cluster", map[string]*llx.RawData{
		"id": llx.StringData(o.cachePrimaryClusterID),
	})
	if err != nil {
		return nil, err
	}
	return mqlCluster.(*mqlOciRedisCluster), nil
}

func (o *mqlOciRedisCluster) subnet() (*mqlOciNetworkSubnet, error) {
	if o.cacheSubnetID == "" {
		o.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlSubnet, err := NewResource(o.MqlRuntime, "oci.network.subnet", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheSubnetID),
	})
	if err != nil {
		return nil, err
	}
	return mqlSubnet.(*mqlOciNetworkSubnet), nil
}

func (o *mqlOciRedisCluster) networkSecurityGroups() ([]any, error) {
	if len(o.cacheNsgIDs) == 0 {
		return []any{}, nil
	}
	res := make([]any, 0, len(o.cacheNsgIDs))
	for _, nsgId := range o.cacheNsgIDs {
		mqlNsg, err := NewResource(o.MqlRuntime, "oci.network.networkSecurityGroup", map[string]*llx.RawData{
			"id": llx.StringData(nsgId),
		})
		if err != nil {
			// Skip an element we cannot resolve rather than failing the whole
			// list and losing the ones that did resolve.
			log.Debug().Err(err).Str("nsg", nsgId).Msg("skipping unresolvable oci reference")
			continue
		}
		res = append(res, mqlNsg)
	}
	return res, nil
}
