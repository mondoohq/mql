// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"maps"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/stackit/connection"
)

// Discovery targets. "auto"/"all" expand to every specific target.
const (
	DiscoveryAuto = "auto"
	DiscoveryAll  = "all"

	DiscoveryServers              = "servers"
	DiscoverySkeClusters          = "ske-clusters"
	DiscoveryObjectStorageBuckets = "object-storage-buckets"
	DiscoveryPostgresFlex         = "postgres-flex-instances"
	DiscoveryMongoDbFlex          = "mongodb-flex-instances"
	DiscoverySqlServerFlex        = "sqlserver-flex-instances"
	DiscoveryOpenSearch           = "opensearch-instances"
	DiscoveryMariaDb              = "mariadb-instances"
	DiscoveryRedis                = "redis-instances"
	DiscoveryRabbitMq             = "rabbitmq-instances"
	DiscoveryLogMe                = "logme-instances"
	DiscoverySecretsManager       = "secrets-manager-instances"
)

// AllDiscoveryTargets is the set "all"/"auto" expand to.
var AllDiscoveryTargets = []string{
	DiscoveryServers,
	DiscoverySkeClusters,
	DiscoveryObjectStorageBuckets,
	DiscoveryPostgresFlex,
	DiscoveryMongoDbFlex,
	DiscoverySqlServerFlex,
	DiscoveryOpenSearch,
	DiscoveryMariaDb,
	DiscoveryRedis,
	DiscoveryRabbitMq,
	DiscoveryLogMe,
	DiscoverySecretsManager,
}

// Discover enumerates STACKIT sub-assets for the connection's discovery targets
// and returns them as a child inventory, mirroring how the aws/gcp providers
// turn cloud resources into individually scannable assets. A failure for one
// target is logged and skipped so the rest of discovery still completes.
func Discover(runtime *plugin.Runtime) (*inventory.Inventory, error) {
	conn, ok := runtime.Connection.(*connection.StackitConnection)
	if !ok {
		return nil, nil
	}

	in := &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: []*inventory.Asset{}}}
	for _, target := range expandTargets(conn.Conf.GetDiscover().GetTargets()) {
		assets, err := discoverTarget(runtime, conn, target)
		if err != nil {
			// A target can legitimately fail when the service is not provisioned
			// in the project/region (the broker returns 404). Log at debug so an
			// optional, unused service does not surface as a scan error; genuine
			// auth/connectivity problems already surface during Verify().
			log.Debug().Err(err).Str("target", target).Msg("stackit> skipping discovery target")
			continue
		}
		for _, a := range assets {
			if a != nil {
				in.Spec.Assets = append(in.Spec.Assets, a)
			}
		}
	}
	return in, nil
}

func expandTargets(targets []string) []string {
	for _, t := range targets {
		if t == DiscoveryAll || t == DiscoveryAuto {
			return AllDiscoveryTargets
		}
	}
	return targets
}

// objectAsset builds a discovered sub-asset from its identifying fields. The
// cloned config carries the parent's credentials with discovery disabled, so the
// sub-asset reconnects through the same project connection.
func objectAsset(conn *connection.StackitConnection, platformName, service, region, id, name string, labels map[string]string) *inventory.Asset {
	if id == "" {
		return nil
	}
	if name == "" {
		name = id
	}
	if region == "" {
		region = conn.Region()
	}

	platformID := connection.MondooObjectID(conn.ProjectID(), service, region, id)

	cfg := conn.Conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.Conf.Id))
	cfg.PlatformId = platformID

	assetLabels := map[string]string{}
	maps.Copy(assetLabels, labels)
	assetLabels["mondoo.com/region"] = region
	assetLabels["mondoo.com/parent-id"] = conn.ProjectID()

	return &inventory.Asset{
		PlatformIds: []string{platformID},
		Name:        name,
		Platform:    connection.GetPlatformForObject(platformName, conn.ProjectID(), service),
		Labels:      assetLabels,
		Connections: []*inventory.Config{cfg},
	}
}

func mapToStringString(m map[string]any) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// discoverTarget enumerates the assets for a single discovery target.
func discoverTarget(runtime *plugin.Runtime, conn *connection.StackitConnection, target string) ([]*inventory.Asset, error) {
	switch target {
	case DiscoveryServers:
		res, err := NewResource(runtime, "stackit", nil)
		if err != nil {
			return nil, err
		}
		list := res.(*mqlStackit).GetServers()
		if list.Error != nil {
			return nil, list.Error
		}
		assets := []*inventory.Asset{}
		for _, item := range list.Data {
			s := item.(*mqlStackitServer)
			assets = append(assets, objectAsset(conn, "stackit-server", "compute", conn.Region(), s.Id.Data, s.Name.Data, mapToStringString(s.Labels.Data)))
		}
		return assets, nil

	case DiscoverySkeClusters:
		res, err := NewResource(runtime, "stackit.ske", nil)
		if err != nil {
			return nil, err
		}
		list := res.(*mqlStackitSke).GetClusters()
		if list.Error != nil {
			return nil, list.Error
		}
		assets := []*inventory.Asset{}
		for _, item := range list.Data {
			c := item.(*mqlStackitSkeCluster)
			// SKE clusters are keyed by name (no separate id field).
			assets = append(assets, objectAsset(conn, "stackit-ske-cluster", "ske", conn.Region(), c.Name.Data, c.Name.Data, nil))
		}
		return assets, nil

	case DiscoveryObjectStorageBuckets:
		res, err := NewResource(runtime, "stackit.objectStorage", nil)
		if err != nil {
			return nil, err
		}
		list := res.(*mqlStackitObjectStorage).GetBuckets()
		if list.Error != nil {
			return nil, list.Error
		}
		assets := []*inventory.Asset{}
		for _, item := range list.Data {
			b := item.(*mqlStackitObjectStorageBucket)
			assets = append(assets, objectAsset(conn, "stackit-object-storage-bucket", "object-storage", b.Region.Data, b.Name.Data, b.Name.Data, nil))
		}
		return assets, nil

	case DiscoveryPostgresFlex:
		res, err := NewResource(runtime, "stackit.postgresFlex", nil)
		if err != nil {
			return nil, err
		}
		list := res.(*mqlStackitPostgresFlex).GetInstances()
		if list.Error != nil {
			return nil, list.Error
		}
		assets := []*inventory.Asset{}
		for _, item := range list.Data {
			i := item.(*mqlStackitPostgresFlexInstance)
			assets = append(assets, objectAsset(conn, "stackit-postgres-flex-instance", "postgres-flex", i.Region.Data, i.Id.Data, i.Name.Data, nil))
		}
		return assets, nil

	case DiscoveryMongoDbFlex:
		res, err := NewResource(runtime, "stackit.mongoDbFlex", nil)
		if err != nil {
			return nil, err
		}
		list := res.(*mqlStackitMongoDbFlex).GetInstances()
		if list.Error != nil {
			return nil, list.Error
		}
		assets := []*inventory.Asset{}
		for _, item := range list.Data {
			i := item.(*mqlStackitMongoDbFlexInstance)
			assets = append(assets, objectAsset(conn, "stackit-mongodb-flex-instance", "mongodb-flex", i.Region.Data, i.Id.Data, i.Name.Data, nil))
		}
		return assets, nil

	case DiscoverySqlServerFlex:
		res, err := NewResource(runtime, "stackit.sqlServerFlex", nil)
		if err != nil {
			return nil, err
		}
		list := res.(*mqlStackitSqlServerFlex).GetInstances()
		if list.Error != nil {
			return nil, list.Error
		}
		assets := []*inventory.Asset{}
		for _, item := range list.Data {
			i := item.(*mqlStackitSqlServerFlexInstance)
			assets = append(assets, objectAsset(conn, "stackit-sqlserver-flex-instance", "sqlserver-flex", i.Region.Data, i.Id.Data, i.Name.Data, nil))
		}
		return assets, nil

	case DiscoveryOpenSearch:
		res, err := NewResource(runtime, "stackit.openSearch", nil)
		if err != nil {
			return nil, err
		}
		list := res.(*mqlStackitOpenSearch).GetInstances()
		if list.Error != nil {
			return nil, list.Error
		}
		assets := []*inventory.Asset{}
		for _, item := range list.Data {
			i := item.(*mqlStackitOpenSearchInstance)
			assets = append(assets, objectAsset(conn, "stackit-opensearch-instance", "opensearch", "", i.Id.Data, i.Name.Data, nil))
		}
		return assets, nil

	case DiscoveryMariaDb:
		res, err := NewResource(runtime, "stackit.mariaDb", nil)
		if err != nil {
			return nil, err
		}
		list := res.(*mqlStackitMariaDb).GetInstances()
		if list.Error != nil {
			return nil, list.Error
		}
		assets := []*inventory.Asset{}
		for _, item := range list.Data {
			i := item.(*mqlStackitMariaDbInstance)
			assets = append(assets, objectAsset(conn, "stackit-mariadb-instance", "mariadb", "", i.Id.Data, i.Name.Data, nil))
		}
		return assets, nil

	case DiscoveryRedis:
		res, err := NewResource(runtime, "stackit.redis", nil)
		if err != nil {
			return nil, err
		}
		list := res.(*mqlStackitRedis).GetInstances()
		if list.Error != nil {
			return nil, list.Error
		}
		assets := []*inventory.Asset{}
		for _, item := range list.Data {
			i := item.(*mqlStackitRedisInstance)
			assets = append(assets, objectAsset(conn, "stackit-redis-instance", "redis", "", i.Id.Data, i.Name.Data, nil))
		}
		return assets, nil

	case DiscoveryRabbitMq:
		res, err := NewResource(runtime, "stackit.rabbitMq", nil)
		if err != nil {
			return nil, err
		}
		list := res.(*mqlStackitRabbitMq).GetInstances()
		if list.Error != nil {
			return nil, list.Error
		}
		assets := []*inventory.Asset{}
		for _, item := range list.Data {
			i := item.(*mqlStackitRabbitMqInstance)
			assets = append(assets, objectAsset(conn, "stackit-rabbitmq-instance", "rabbitmq", "", i.Id.Data, i.Name.Data, nil))
		}
		return assets, nil

	case DiscoveryLogMe:
		res, err := NewResource(runtime, "stackit.logMe", nil)
		if err != nil {
			return nil, err
		}
		list := res.(*mqlStackitLogMe).GetInstances()
		if list.Error != nil {
			return nil, list.Error
		}
		assets := []*inventory.Asset{}
		for _, item := range list.Data {
			i := item.(*mqlStackitLogMeInstance)
			assets = append(assets, objectAsset(conn, "stackit-logme-instance", "logme", "", i.Id.Data, i.Name.Data, nil))
		}
		return assets, nil

	case DiscoverySecretsManager:
		res, err := NewResource(runtime, "stackit.secretsManager", nil)
		if err != nil {
			return nil, err
		}
		list := res.(*mqlStackitSecretsManager).GetInstances()
		if list.Error != nil {
			return nil, list.Error
		}
		assets := []*inventory.Asset{}
		for _, item := range list.Data {
			i := item.(*mqlStackitSecretsManagerInstance)
			assets = append(assets, objectAsset(conn, "stackit-secrets-manager-instance", "secrets-manager", "", i.Id.Data, i.Name.Data, nil))
		}
		return assets, nil

	default:
		log.Warn().Str("target", target).Msg("stackit> unknown discovery target")
		return nil, nil
	}
}
