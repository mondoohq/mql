// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"
	"time"

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
					CompartmentId: new(compartmentID),
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
					"lifecycleDetails":           llx.StringDataPtr(c.LifecycleDetails),
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
				mqlClusterTyped.cacheSecurityAttributes = definedTagsToAny(c.SecurityAttributes)
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
	// cacheSecurityAttributes holds the Zero Trust Packet Routing attributes
	// from the listing, in the namespace-keyed shape the applied-attribute
	// resolver and the exposure take.
	cacheSecurityAttributes map[string]any
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
	return ociRedisClusterSubnet(o.State.Data, func() *plugin.TValue[[]any] {
		obj, err := CreateResource(o.MqlRuntime, "oci.network", nil)
		if err != nil {
			return &plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet}
		}
		return obj.(*mqlOciNetwork).GetSubnets()
	}, o.cacheSubnetID, &o.Subnet)
}

// ociRedisClusterSubnet resolves a cache cluster's subnet through the subnet
// listing. The listing keeps reporting a cluster for a while after it is
// DELETED, and its subnet is often deleted with it. Both are an absence, not
// a failure: a DELETED cluster has no subnet, and a subnet the listing does
// not hold reads as null instead of the not-found error the subnet init
// raises. The listing is not read for a DELETED cluster.
func ociRedisClusterSubnet(state string, subnets func() *plugin.TValue[[]any], id string, field *plugin.TValue[*mqlOciNetworkSubnet]) (*mqlOciNetworkSubnet, error) {
	if id == "" || state == string(redis.RedisClusterLifecycleStateDeleted) {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return ociListedRef(subnets(), id, field)
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

func (o *mqlOciRedisCluster) region() (*mqlOciRegion, error) {
	return resolveOciRegionByKey(o.MqlRuntime, o.cacheRegion, &o.Region)
}

func (o *mqlOciRedisCluster) appliedSecurityAttributes() ([]any, error) {
	return ociAppliedSecurityAttributes(o.MqlRuntime, o.Id.Data, o.cacheSecurityAttributes)
}

// exposure breaks down whether the cluster's endpoints are reachable from the
// internet. OCI Cache gives a cluster private endpoint addresses only, so
// hasPublicIp is false and so is internetReachable; the subnet, security list
// and network security group parts are still reported.
func (o *mqlOciRedisCluster) exposure() (*mqlOciNetworkExposure, error) {
	// A DELETED cluster stays in the listing for a while but has no
	// endpoints left to expose, and its subnet is usually gone with it.
	if o.State.Data == string(redis.RedisClusterLifecycleStateDeleted) {
		o.Exposure.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	subnet := o.GetSubnet()
	if subnet.Error != nil {
		return nil, subnet.Error
	}
	nsgs := o.GetNetworkSecurityGroups()
	if nsgs.Error != nil {
		return nil, nsgs.Error
	}
	return ociSubnetEndpointExposure(o.MqlRuntime,
		"oci.redis.cluster/"+o.Id.Data+"/exposure",
		false, subnet.Data, nsgs.Data, o.cacheSecurityAttributes)
}

// users lists the cache users attached to the cluster. The attachment call
// returns only user OCIDs, which are resolved against the cache user listing
// rather than read one by one.
func (o *mqlOciRedisCluster) users() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	svc, err := conn.RedisClusterClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}

	attached, err := ociPaginate(context.Background(), func(ctx context.Context, page *string) ([]redis.AttachedOciCacheUser, *string, error) {
		response, err := svc.ListAttachedOciCacheUsers(ctx, redis.ListAttachedOciCacheUsersRequest{
			RedisClusterId: new(o.Id.Data),
			Page:           page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(attached))
	for _, a := range attached {
		id := stringValue(a.OciCacheUserId)
		if id == "" {
			continue
		}
		user, err := NewResource(o.MqlRuntime, "oci.redis.user", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			// A user in a compartment the scan does not reach cannot be
			// resolved; keep the ones that can.
			log.Debug().Err(err).Str("user", id).Msg("skipping unresolvable oci cache user")
			continue
		}
		res = append(res, user)
	}
	return res, nil
}

func (o *mqlOciRedis) users() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			svc, err := conn.OciCacheUserClient(region)
			if err != nil {
				return nil, err
			}

			users, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]redis.OciCacheUserSummary, *string, error) {
				response, err := svc.ListOciCacheUsers(ctx, redis.ListOciCacheUsersRequest{
					CompartmentId: new(compartmentID),
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

			res := make([]any, 0, len(users))
			for i := range users {
				u := users[i]
				if conn.Filters.IsFilteredOutByTags(u.FreeformTags, u.DefinedTags) {
					continue
				}
				mqlUser, err := createOciResourceInCompartment(o.MqlRuntime, "oci.redis.user", stringValue(u.CompartmentId), map[string]*llx.RawData{
					"id":                 llx.StringDataPtr(u.Id),
					"name":               llx.StringDataPtr(u.Name),
					"description":        llx.StringDataPtr(u.Description),
					"authenticationType": llx.StringData(string(u.AuthenticationType)),
					"status":             llx.StringData(string(u.Status)),
					"state":              llx.StringData(string(u.LifecycleState)),
					"created":            sdkTimeData(u.TimeCreated),
					"freeformTags":       llx.MapData(strMapToAny(u.FreeformTags), types.String),
					"definedTags":        llx.MapData(definedTagsToAny(u.DefinedTags), types.Any),
					"systemTags":         llx.MapData(definedTagsToAny(u.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				typed := mqlUser.(*mqlOciRedisUser)
				typed.cacheRegion = region
				res = append(res, typed)
			}
			return res, nil
		})
}

type mqlOciRedisUserInternal struct {
	ociCompartmentRef
	cacheRegion string
	detail      ociRetryLazy[*redis.OciCacheUser]
}

func (o *mqlOciRedisUser) id() (string, error) {
	return "oci.redis.user/" + o.Id.Data, nil
}

func initOciRedisUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, resolve := ociInitArgs(args)
	if !resolve {
		return args, nil, nil
	}
	items, err := ociServiceCollection(runtime, "oci.redis", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciRedis).GetUsers()
	})
	if err != nil {
		return nil, nil, err
	}
	return ociResolveByID(args, "oci.redis.user", id, items)
}

// aclString reads the user's access control list, which only the detail call
// returns. The detail also carries the password hashes of a PASSWORD user;
// those are never read out of it.
func (o *mqlOciRedisUser) aclString() (string, error) {
	u, err := o.detail.get(func() (*redis.OciCacheUser, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		svc, err := conn.OciCacheUserClient(o.cacheRegion)
		if err != nil {
			return nil, err
		}
		resp, err := svc.GetOciCacheUser(context.Background(), redis.GetOciCacheUserRequest{
			OciCacheUserId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.OciCacheUser, nil
	})
	if err != nil || u == nil {
		return "", err
	}
	return ociRedactRedisACL(stringValue(u.AclString)), nil
}

// ociRedisACLKeywords are the Redis ACL rules that are a bare keyword and
// carry no value.
var ociRedisACLKeywords = map[string]bool{
	"on": true, "off": true, "nopass": true, "resetpass": true, "reset": true,
	"resetkeys": true, "resetchannels": true, "allkeys": true, "allchannels": true,
	"allcommands": true, "nocommands": true, "sanitize-payload": true,
	"skip-sanitize-payload": true, "clearselectors": true,
}

// ociRedisACLRuleKnown reports whether a token is a Redis ACL rule that
// carries no credential: a keyword, a key pattern (`~`, or `%R~`, `%W~`,
// `%RW~` with permissions), a channel pattern (`&`), or a command or
// category rule (`+`, `-`). Selector parentheses are stripped first, so the
// rules inside `(~key* +get)` are judged one by one.
func ociRedisACLRuleKnown(token string) bool {
	core := strings.TrimSuffix(strings.TrimPrefix(token, "("), ")")
	if core == "" {
		return token != ""
	}
	if ociRedisACLKeywords[strings.ToLower(core)] {
		return true
	}
	switch core[0] {
	case '~', '%', '&', '+', '-':
		return true
	}
	return false
}

// ociRedactRedisACL masks the credentials in a Redis ACL and fails closed.
//
// The ACL syntax lets a rule carry a credential inline: `>password` and
// `<password` add and remove a plaintext password, `#hash` and `!hash` a
// SHA-256 hash of one. Nothing in the OCI Cache API documents that such rules
// are rejected or redacted in aclString. A password sent as a single argument
// may contain spaces, so splitting on whitespace cannot tell where it ends.
// Only rules known to carry no credential are therefore kept as written. A
// password rule becomes its prefix followed by `***`, and the unrecognized
// tokens after it, which may be the rest of the password, fold into that
// mask. Any other unrecognized token becomes `***`.
func ociRedactRedisACL(acl string) string {
	out := []string{}
	inPassword := false
	for _, token := range strings.Fields(acl) {
		switch {
		case strings.ContainsRune("><#!", rune(token[0])):
			out = append(out, token[:1]+"***")
			inPassword = true
		case ociRedisACLRuleKnown(token):
			out = append(out, token)
			inPassword = false
		case inPassword:
			// Part of the password rule before it, already masked.
		default:
			out = append(out, "***")
		}
	}
	return strings.Join(out, " ")
}
