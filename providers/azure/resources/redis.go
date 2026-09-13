// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis/v4"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAzureSubscriptionCacheService) id() (string, error) {
	return "azure.subscription.cache/" + a.SubscriptionId.Data, nil
}

type mqlAzureSubscriptionCacheServiceRedisInstanceInternal struct {
	cachePrivateEndpointConnections []*armredis.PrivateEndpointConnection
	cacheUserAssignedIdentityIds    []string
	cacheLinkedServerIds            []string
	cacheSystemData                 any
}

func (a *mqlAzureSubscriptionCacheServiceRedisInstance) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionCacheServiceRedisInstance) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

func (a *mqlAzureSubscriptionCacheServiceRedisInstance) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	if a.SubnetId.Data == "" {
		a.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.subnet",
		map[string]*llx.RawData{"id": llx.StringData(a.SubnetId.Data)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceSubnet), nil
}

func initAzureSubscriptionCacheService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	args["subscriptionId"] = llx.StringData(conn.SubId())

	return args, nil, nil
}

func initAzureSubscriptionCacheServiceRedisInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromServiceList(runtime, args,
		ResourceAzureSubscriptionCacheService,
		func(s *mqlAzureSubscriptionCacheService) *plugin.TValue[[]any] { return s.GetRedis() },
		ResourceAzureSubscriptionCacheServiceRedisInstance)
}

func (a *mqlAzureSubscriptionCacheService) redis() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()

	subscriptionID := a.SubscriptionId.Data

	clientFactory, err := armredis.NewClientFactory(subscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	client := clientFactory.NewClient()
	cachePager := client.NewListBySubscriptionPager(nil)
	var caches []any

	for cachePager.More() {
		page, err := cachePager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, cache := range page.Value {
			if cache == nil {
				continue
			}

			rawData, err := createRedisInstanceRawData(a.MqlRuntime, cache)
			if err != nil {
				return nil, err
			}

			cacheData, err := CreateResource(
				a.MqlRuntime,
				"azure.subscription.cacheService.redisInstance",
				rawData,
			)
			if err != nil {
				return nil, err
			}
			mqlRedis := cacheData.(*mqlAzureSubscriptionCacheServiceRedisInstance)
			if cache.Properties != nil {
				mqlRedis.cachePrivateEndpointConnections = cache.Properties.PrivateEndpointConnections
				linkedIds := []string{}
				for _, ls := range cache.Properties.LinkedServers {
					if ls != nil && ls.ID != nil {
						linkedIds = append(linkedIds, *ls.ID)
					}
				}
				mqlRedis.cacheLinkedServerIds = linkedIds
			}
			if cache.Identity != nil {
				mqlRedis.cacheUserAssignedIdentityIds = sortedUserAssignedIdentityIDs(cache.Identity.UserAssignedIdentities)
			}
			sysData, err := convert.JsonToDict(cache.SystemData)
			if err != nil {
				return nil, err
			}
			mqlRedis.cacheSystemData = sysData
			caches = append(caches, mqlRedis)
		}
	}

	return caches, nil
}

// redactedRedisConfiguration copies a cache's Redis configuration with the
// persistence storage connection strings removed.
//
// Azure returns all three verbatim, and each carries either an account key or a
// SAS token for the storage account holding the RDB/AOF backups. They reached
// MQL twice -- once through redisConfiguration and again through properties,
// which serializes the whole ResourceInfo -- so anyone printing either field
// printed the storage credential.
//
// The copy is by field rather than by JSON key so that a field renamed in a
// future SDK breaks the build instead of silently leaking again. Everything
// else in the configuration is kept, including rdbBackupEnabled, so the audit
// signal survives the redaction.
func redactedRedisConfiguration(cfg *armredis.CommonPropertiesRedisConfiguration) *armredis.CommonPropertiesRedisConfiguration {
	if cfg == nil {
		return nil
	}
	safe := *cfg
	safe.AofStorageConnectionString0 = nil
	safe.AofStorageConnectionString1 = nil
	safe.RdbStorageConnectionString = nil
	return &safe
}

// redactedRedisResource copies a cache with its configuration redacted, for the
// properties bag that serializes the whole record.
func redactedRedisResource(cache *armredis.ResourceInfo) *armredis.ResourceInfo {
	if cache == nil {
		return nil
	}
	safe := *cache
	if cache.Properties != nil {
		props := *cache.Properties
		props.RedisConfiguration = redactedRedisConfiguration(cache.Properties.RedisConfiguration)
		safe.Properties = &props
	}
	return &safe
}

func createRedisInstanceRawData(runtime *plugin.Runtime, cache *armredis.ResourceInfo) (map[string]*llx.RawData, error) {
	// Properties is a nullable pointer that the field reads below dereference
	// throughout; normalize to an empty struct so a cache returned without
	// properties doesn't panic here (the callers reach this before their own
	// nil guards).
	//
	// Normalize onto a local copy rather than writing back through the pointer.
	// The caller keeps using its own *ResourceInfo after this returns -- to seed
	// the resource's caches, behind an `if cache.Properties != nil` guard -- so
	// filling the field in here would turn that guard into a read of an empty
	// struct, and would contradict what the redaction helpers below promise
	// about leaving the source alone.
	if cache.Properties == nil {
		normalized := *cache
		normalized.Properties = &armredis.Properties{}
		cache = &normalized
	}
	properties, err := convert.JsonToDict(redactedRedisResource(cache))
	if err != nil {
		return nil, err
	}

	sku, err := convert.JsonToDict(cache.Properties.SKU)
	if err != nil {
		return nil, err
	}
	// publicNetworkAccess is an enum with possible values: Enabled, Disabled
	var publicNetworkAccess *string
	if cache.Properties.PublicNetworkAccess != nil {
		val := string(*cache.Properties.PublicNetworkAccess)
		publicNetworkAccess = &val
	}
	// provisioningState is an enum with possible values: Creating, Deleting, Failed, Succeeded, Updating
	var provisioningState *string
	if cache.Properties.ProvisioningState != nil {
		val := string(*cache.Properties.ProvisioningState)
		provisioningState = &val
	}
	// minimumTlsVersion is an enum with possible values: "1.0", "1.1", "1.2"
	var minimumTlsVersion *string
	if cache.Properties.MinimumTLSVersion != nil {
		val := string(*cache.Properties.MinimumTLSVersion)
		minimumTlsVersion = &val
	}

	redisConfiguration, err := convert.JsonToDict(redactedRedisConfiguration(cache.Properties.RedisConfiguration))
	if err != nil {
		return nil, err
	}

	identity, err := convert.JsonToDict(cache.Identity)
	if err != nil {
		return nil, err
	}

	cacheIdentity := orZero(cache.Identity)

	zones := []any{}
	for _, z := range cache.Zones {
		if z != nil {
			zones = append(zones, *z)
		}
	}

	args := map[string]*llx.RawData{
		"id":                  llx.StringDataPtr(cache.ID),
		"name":                llx.StringDataPtr(cache.Name),
		"type":                llx.StringDataPtr(cache.Type),
		"location":            llx.StringDataPtr(cache.Location),
		"properties":          llx.DictData(properties),
		"hostName":            llx.StringDataPtr(cache.Properties.HostName),
		"enableNonSslPort":    llx.BoolDataPtr(cache.Properties.EnableNonSSLPort),
		"publicNetworkAccess": llx.StringDataPtr(publicNetworkAccess),
		"port":                llx.IntDataPtr(cache.Properties.Port),
		"sslPort":             llx.IntDataPtr(cache.Properties.SSLPort),
		"provisioningState":   llx.StringDataPtr(provisioningState),
		"redisVersion":        llx.StringDataPtr(cache.Properties.RedisVersion),
		"replicasPerMaster":   llx.IntDataPtr(cache.Properties.ReplicasPerMaster),
		"replicasPerPrimary":  llx.IntDataPtr(cache.Properties.ReplicasPerPrimary),
		"sku":                 llx.DictData(sku),
		"tags":                llx.MapData(convert.PtrMapStrToInterface(cache.Tags), types.String),
		"minimumTlsVersion":   llx.StringDataPtr(minimumTlsVersion),
		"redisConfiguration":  llx.DictData(redisConfiguration),
		"shardCount":          llx.IntDataPtr(cache.Properties.ShardCount),
		"staticIp":            llx.StringDataPtr(cache.Properties.StaticIP),
		"subnetId":            llx.StringDataPtr(cache.Properties.SubnetID),
		"zones":               llx.ArrayData(zones, types.String),
		"identity":            llx.DictData(identity),
		"principalId":         llx.StringDataPtr(cacheIdentity.PrincipalID),

		"disableAccessKeyAuthentication": llx.BoolDataPtr(cache.Properties.DisableAccessKeyAuthentication),
		"updateChannel":                  llx.StringDataPtr(stringEnumPtr(cache.Properties.UpdateChannel)),
		"zonalAllocationPolicy":          llx.StringDataPtr(stringEnumPtr(cache.Properties.ZonalAllocationPolicy)),
		"tenantSettings":                 llx.MapData(convert.PtrMapStrToInterface(cache.Properties.TenantSettings), types.String),
	}
	redisSku := orZero(cache.Properties.SKU)
	if err := setSkuData(runtime, args, skuName(redisSku.Name), skuFamily(redisSku.Family), skuCapacity(redisSku.Capacity)); err != nil {
		return nil, err
	}
	if err := setResourceIdentity(runtime, args, sortedUserAssignedIdentityIDs(cacheIdentity.UserAssignedIdentities),
		identityType(cacheIdentity.Type), identityPrincipalId(cacheIdentity.PrincipalID), identityTenantId(cacheIdentity.TenantID)); err != nil {
		return nil, err
	}
	if err := setRedisConfigurationRef(runtime, args, cache.Properties.RedisConfiguration); err != nil {
		return nil, err
	}

	return args, nil
}

// setRedisConfigurationRef publishes the Redis server settings as a child
// resource of the cache.
//
// The storage connection strings on this block are credentials and are
// deliberately not modeled; the auth method that selects between them is what
// an audit needs.
func setRedisConfigurationRef(runtime *plugin.Runtime, args map[string]*llx.RawData, cfg *armredis.CommonPropertiesRedisConfiguration) error {
	if cfg == nil {
		args["configuration"] = llx.NilData
		return nil
	}
	parentID := subResourceParentKey(args)
	if parentID == "" {
		return errors.New("cannot key the Redis configuration: the cache has no id")
	}
	res, err := CreateResource(runtime, "azure.subscription.cacheService.redisInstance.configuration",
		map[string]*llx.RawData{
			"__id":                               llx.StringData(parentID + "/redisConfiguration"),
			"authNotRequired":                    llx.StringDataPtr(cfg.Authnotrequired),
			"aadEnabled":                         llx.StringDataPtr(cfg.AADEnabled),
			"maxmemoryPolicy":                    llx.StringDataPtr(cfg.MaxmemoryPolicy),
			"rdbBackupEnabled":                   llx.StringDataPtr(cfg.RdbBackupEnabled),
			"rdbBackupFrequency":                 llx.StringDataPtr(cfg.RdbBackupFrequency),
			"aofBackupEnabled":                   llx.StringDataPtr(cfg.AofBackupEnabled),
			"preferredDataPersistenceAuthMethod": llx.StringDataPtr(cfg.PreferredDataPersistenceAuthMethod),
		})
	if err != nil {
		return err
	}
	args["configuration"] = llx.ResourceData(res, "azure.subscription.cacheService.redisInstance.configuration")
	return nil
}

// linkedServers resolves the caches this one is geo-replicated with, so a
// replica's own TLS and network settings can be read rather than assumed to
// match this cache's.
func (a *mqlAzureSubscriptionCacheServiceRedisInstance) linkedServers() ([]any, error) {
	res := []any{}
	for _, id := range a.cacheLinkedServerIds {
		if id == "" {
			continue
		}
		linked, err := NewResource(a.MqlRuntime, "azure.subscription.cacheService.redisInstance",
			map[string]*llx.RawData{"id": llx.StringData(id)})
		if err != nil {
			// A linked cache in a subscription this credential cannot read is a
			// supported configuration. Skip it rather than failing the cache.
			log.Warn().Err(err).Str("id", id).Msg("could not resolve linked Redis cache")
			continue
		}
		res = append(res, linked)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCacheServiceRedisInstance) privateEndpointConnections() ([]any, error) {
	res := []any{}
	for _, pec := range a.cachePrivateEndpointConnections {
		if pec == nil {
			continue
		}
		var privateEndpointId *string
		if pec.Properties != nil && pec.Properties.PrivateEndpoint != nil {
			privateEndpointId = pec.Properties.PrivateEndpoint.ID
		}
		var status *string
		if pec.Properties != nil && pec.Properties.PrivateLinkServiceConnectionState != nil && pec.Properties.PrivateLinkServiceConnectionState.Status != nil {
			val := string(*pec.Properties.PrivateLinkServiceConnectionState.Status)
			status = &val
		}
		var description *string
		if pec.Properties != nil && pec.Properties.PrivateLinkServiceConnectionState != nil {
			description = pec.Properties.PrivateLinkServiceConnectionState.Description
		}
		var pecProvisioningState *string
		if pec.Properties != nil && pec.Properties.ProvisioningState != nil {
			val := string(*pec.Properties.ProvisioningState)
			pecProvisioningState = &val
		}
		groupIds := []any{}
		if pec.Properties != nil {
			for _, g := range pec.Properties.GroupIDs {
				if g != nil {
					groupIds = append(groupIds, *g)
				}
			}
		}
		pecResource, err := CreateResource(a.MqlRuntime, "azure.subscription.cacheService.redisInstance.privateEndpointConnection",
			map[string]*llx.RawData{
				"id":                llx.StringDataPtr(pec.ID),
				"name":              llx.StringDataPtr(pec.Name),
				"type":              llx.StringDataPtr(pec.Type),
				"status":            llx.StringDataPtr(status),
				"description":       llx.StringDataPtr(description),
				"provisioningState": llx.StringDataPtr(pecProvisioningState),
				"groupIds":          llx.ArrayData(groupIds, types.String),
			})
		if err != nil {
			return nil, err
		}
		sysData, err := convert.JsonToDict(pec.SystemData)
		if err != nil {
			return nil, err
		}
		mqlPec := pecResource.(*mqlAzureSubscriptionCacheServiceRedisInstancePrivateEndpointConnection)
		mqlPec.cacheSystemData = sysData
		mqlPec.cachePrivateEndpointId = convert.ToValue(privateEndpointId)
		res = append(res, pecResource)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCacheServiceRedisInstance) firewallRules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	cacheName, err := resourceID.Component("redis")
	if err != nil {
		return nil, err
	}

	firewallClient, err := armredis.NewFirewallRulesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := firewallClient.NewListPager(resourceID.ResourceGroup, cacheName, nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
				return []any{}, nil
			}
			return nil, err
		}
		for _, rule := range page.Value {
			if rule == nil {
				continue
			}
			var startIP, endIP *string
			if rule.Properties != nil {
				startIP = rule.Properties.StartIP
				endIP = rule.Properties.EndIP
			}
			args := map[string]*llx.RawData{
				"id":             llx.StringDataPtr(rule.ID),
				"name":           llx.StringDataPtr(rule.Name),
				"type":           llx.StringDataPtr(rule.Type),
				"startIpAddress": llx.StringDataPtr(startIP),
				"endIpAddress":   llx.StringDataPtr(endIP),
			}
			mqlRule, err := CreateResource(a.MqlRuntime, "azure.subscription.cacheService.redisInstance.firewallRule", args)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(rule.SystemData)
			if err != nil {
				return nil, err
			}
			mqlRule.(*mqlAzureSubscriptionCacheServiceRedisInstanceFirewallRule).cacheSystemData = sysData
			res = append(res, mqlRule)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCacheServiceRedisInstance) patchSchedules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	cacheName, err := resourceID.Component("redis")
	if err != nil {
		return nil, err
	}

	patchClient, err := armredis.NewPatchSchedulesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := patchClient.NewListByRedisResourcePager(resourceID.ResourceGroup, cacheName, nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
				return []any{}, nil
			}
			return nil, err
		}
		for _, schedule := range page.Value {
			if schedule == nil {
				continue
			}

			entries := []any{}
			if schedule.Properties != nil {
				for _, entry := range schedule.Properties.ScheduleEntries {
					if entry == nil {
						continue
					}
					entryDict, err := convert.JsonToDict(entry)
					if err != nil {
						return nil, err
					}
					entries = append(entries, entryDict)
				}
			}

			mqlSchedule, err := CreateResource(a.MqlRuntime, "azure.subscription.cacheService.redisInstance.patchSchedule",
				map[string]*llx.RawData{
					"id":       llx.StringDataPtr(schedule.ID),
					"name":     llx.StringDataPtr(schedule.Name),
					"location": llx.StringDataPtr(schedule.Location),
					"entries":  llx.ArrayData(entries, types.Dict),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(schedule.SystemData)
			if err != nil {
				return nil, err
			}
			mqlSchedule.(*mqlAzureSubscriptionCacheServiceRedisInstancePatchSchedule).cacheSystemData = sysData
			res = append(res, mqlSchedule)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCacheServiceRedisInstanceFirewallRule) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionCacheServiceRedisInstanceFirewallRuleInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCacheServiceRedisInstanceFirewallRule) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCacheServiceRedisInstancePatchSchedule) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionCacheServiceRedisInstancePatchScheduleInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCacheServiceRedisInstancePatchSchedule) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCacheServiceRedisInstancePrivateEndpointConnection) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionCacheServiceRedisInstancePrivateEndpointConnectionInternal struct {
	cacheSystemData        any
	cachePrivateEndpointId string
}

func (a *mqlAzureSubscriptionCacheServiceRedisInstancePrivateEndpointConnection) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCacheServiceRedisInstancePrivateEndpointConnection) privateEndpoint() (*mqlAzureSubscriptionNetworkServicePrivateEndpoint, error) {
	peId := a.cachePrivateEndpointId
	if peId == "" {
		a.PrivateEndpoint.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.privateEndpoint", map[string]*llx.RawData{
		"id": llx.StringData(peId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServicePrivateEndpoint), nil
}
