// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// Discovery targets recognized by the alicloud provider. `accounts` yields the
// account asset the connection targets; the fine-grained targets turn each
// major service object into its own scannable asset. `auto` and `all` expand to
// every fine-grained target.
const (
	DiscoveryAuto          = "auto"
	DiscoveryAll           = "all"
	DiscoveryAccounts      = "accounts"
	DiscoveryK8sClusters   = "k8s-clusters"
	DiscoveryAlbs          = "albs"
	DiscoveryNlbs          = "nlbs"
	DiscoveryVpcs          = "vpcs"
	DiscoveryWaf           = "waf"
	DiscoveryCloudFirewall = "cloud-firewall"
	DiscoveryOssBuckets    = "oss-buckets"
	DiscoveryRdsInstances  = "rds-instances"

	DiscoverySlbs             = "slbs"
	DiscoveryRedisInstances   = "redis-instances"
	DiscoveryMongodbInstances = "mongodb-instances"
	DiscoveryPolardbClusters  = "polardb-clusters"
	DiscoveryFcFunctions      = "fc-functions"
	DiscoveryAcrInstances     = "acr-instances"
	DiscoveryEsClusters       = "es-clusters"
)

// Discover enumerates the major service objects in the account and returns one
// child asset per object, scoped to that object's region with further discovery
// disabled. The account itself is always the connected root asset, so the
// `accounts` target produces no discovered children.
func Discover(runtime *plugin.Runtime, conf *inventory.Config) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.AlicloudConnection)

	in := &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: []*inventory.Asset{}}}
	if conf.Discover == nil || len(conf.Discover.Targets) == 0 {
		return in, nil
	}

	for _, target := range handleTargets(conf.Discover.Targets) {
		var assets []*inventory.Asset
		var err error
		switch target {
		case DiscoveryK8sClusters:
			assets, err = discoverAckClusters(runtime, conn, conf)
		case DiscoveryAlbs:
			assets, err = discoverAlbs(runtime, conn, conf)
		case DiscoveryNlbs:
			assets, err = discoverNlbs(runtime, conn, conf)
		case DiscoveryVpcs:
			assets, err = discoverVpcs(runtime, conn, conf)
		case DiscoveryWaf:
			assets, err = discoverWaf(runtime, conn, conf)
		case DiscoveryCloudFirewall:
			assets, err = discoverCloudFirewall(runtime, conn, conf)
		case DiscoveryOssBuckets:
			assets, err = discoverOssBuckets(runtime, conn, conf)
		case DiscoveryRdsInstances:
			assets, err = discoverRdsInstances(runtime, conn, conf)
		case DiscoverySlbs:
			assets, err = discoverSlbs(runtime, conn, conf)
		case DiscoveryRedisInstances:
			assets, err = discoverRedisInstances(runtime, conn, conf)
		case DiscoveryMongodbInstances:
			assets, err = discoverMongodbInstances(runtime, conn, conf)
		case DiscoveryPolardbClusters:
			assets, err = discoverPolardbClusters(runtime, conn, conf)
		case DiscoveryFcFunctions:
			assets, err = discoverFcFunctions(runtime, conn, conf)
		case DiscoveryAcrInstances:
			assets, err = discoverAcrInstances(runtime, conn, conf)
		case DiscoveryEsClusters:
			assets, err = discoverEsClusters(runtime, conn, conf)
		case DiscoveryAccounts:
			// the account is already returned as the connected root asset, so it
			// contributes no discovered child assets
			continue
		default:
			continue
		}
		if err != nil {
			return nil, err
		}
		in.Spec.Assets = append(in.Spec.Assets, assets...)
	}

	return in, nil
}

// handleTargets expands `auto`/`all` into every fine-grained target.
func handleTargets(targets []string) []string {
	if stringx.ContainsAnyOf(targets, DiscoveryAll, DiscoveryAuto) {
		return []string{
			DiscoveryK8sClusters,
			DiscoveryAlbs,
			DiscoveryNlbs,
			DiscoveryVpcs,
			DiscoveryWaf,
			DiscoveryCloudFirewall,
			DiscoveryOssBuckets,
			DiscoveryRdsInstances,
			DiscoverySlbs,
			DiscoveryRedisInstances,
			DiscoveryMongodbInstances,
			DiscoveryPolardbClusters,
			DiscoveryFcFunctions,
			DiscoveryAcrInstances,
			DiscoveryEsClusters,
		}
	}
	return targets
}

func discoverAckClusters(runtime *plugin.Runtime, conn *connection.AlicloudConnection, conf *inventory.Config) ([]*inventory.Asset, error) {
	res, err := CreateResource(runtime, "alicloud.cs", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	clusters, err := res.(*mqlAlicloudCs).clusters()
	if err != nil {
		return nil, err
	}
	assets := make([]*inventory.Asset, 0, len(clusters))
	for _, ic := range clusters {
		cluster := ic.(*mqlAlicloudCsCluster)
		id := cluster.ClusterId.Data
		if id == "" {
			continue
		}
		assets = append(assets, newChildAsset(conf, conn.ID(), cluster.RegionId.Data,
			connection.NewAckClusterIdentifier(id), connection.NewAckClusterPlatform(id),
			nameOr(cluster.Name.Data, id), connection.OptionClusterID, id))
	}
	return assets, nil
}

func discoverAlbs(runtime *plugin.Runtime, conn *connection.AlicloudConnection, conf *inventory.Config) ([]*inventory.Asset, error) {
	res, err := CreateResource(runtime, "alicloud.alb", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	lbs, err := res.(*mqlAlicloudAlb).loadBalancers()
	if err != nil {
		return nil, err
	}
	assets := make([]*inventory.Asset, 0, len(lbs))
	for _, il := range lbs {
		lb := il.(*mqlAlicloudAlbLoadBalancer)
		id := lb.LoadBalancerId.Data
		if id == "" {
			continue
		}
		assets = append(assets, newChildAsset(conf, conn.ID(), lb.RegionId.Data,
			connection.NewAlbIdentifier(id), connection.NewAlbPlatform(id),
			nameOr(lb.Name.Data, id), connection.OptionAlbID, id))
	}
	return assets, nil
}

func discoverNlbs(runtime *plugin.Runtime, conn *connection.AlicloudConnection, conf *inventory.Config) ([]*inventory.Asset, error) {
	res, err := CreateResource(runtime, "alicloud.nlb", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	lbs, err := res.(*mqlAlicloudNlb).loadBalancers()
	if err != nil {
		return nil, err
	}
	assets := make([]*inventory.Asset, 0, len(lbs))
	for _, il := range lbs {
		lb := il.(*mqlAlicloudNlbLoadBalancer)
		id := lb.LoadBalancerId.Data
		if id == "" {
			continue
		}
		assets = append(assets, newChildAsset(conf, conn.ID(), lb.RegionId.Data,
			connection.NewNlbIdentifier(id), connection.NewNlbPlatform(id),
			nameOr(lb.Name.Data, id), connection.OptionNlbID, id))
	}
	return assets, nil
}

func discoverVpcs(runtime *plugin.Runtime, conn *connection.AlicloudConnection, conf *inventory.Config) ([]*inventory.Asset, error) {
	res, err := CreateResource(runtime, "alicloud.vpc", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	networks, err := res.(*mqlAlicloudVpc).networks()
	if err != nil {
		return nil, err
	}
	assets := make([]*inventory.Asset, 0, len(networks))
	for _, in := range networks {
		vpc := in.(*mqlAlicloudVpcNetwork)
		id := vpc.VpcId.Data
		if id == "" {
			continue
		}
		assets = append(assets, newChildAsset(conf, conn.ID(), vpc.RegionId.Data,
			connection.NewVpcIdentifier(id), connection.NewVpcPlatform(id),
			nameOr(vpc.VpcName.Data, id), connection.OptionVpcID, id))
	}
	return assets, nil
}

func discoverOssBuckets(runtime *plugin.Runtime, conn *connection.AlicloudConnection, conf *inventory.Config) ([]*inventory.Asset, error) {
	res, err := CreateResource(runtime, "alicloud.oss", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	buckets, err := res.(*mqlAlicloudOss).buckets()
	if err != nil {
		return nil, err
	}
	assets := make([]*inventory.Asset, 0, len(buckets))
	for _, ib := range buckets {
		bucket := ib.(*mqlAlicloudOssBucket)
		name := bucket.Name.Data
		if name == "" {
			continue
		}
		assets = append(assets, newChildAsset(conf, conn.ID(), bucket.Region.Data,
			connection.NewOssBucketIdentifier(name), connection.NewOssBucketPlatform(name),
			name, connection.OptionOssBucket, name))
	}
	return assets, nil
}

func discoverRdsInstances(runtime *plugin.Runtime, conn *connection.AlicloudConnection, conf *inventory.Config) ([]*inventory.Asset, error) {
	res, err := CreateResource(runtime, "alicloud.rds", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	instances, err := res.(*mqlAlicloudRds).instances()
	if err != nil {
		return nil, err
	}
	assets := make([]*inventory.Asset, 0, len(instances))
	for _, ii := range instances {
		inst := ii.(*mqlAlicloudRdsInstance)
		id := inst.DbInstanceId.Data
		if id == "" {
			continue
		}
		assets = append(assets, newChildAsset(conf, conn.ID(), inst.RegionId.Data,
			connection.NewRdsInstanceIdentifier(id), connection.NewRdsInstancePlatform(id),
			nameOr(inst.DbInstanceDescription.Data, id), connection.OptionRdsInstanceID, id))
	}
	return assets, nil
}

func discoverSlbs(runtime *plugin.Runtime, conn *connection.AlicloudConnection, conf *inventory.Config) ([]*inventory.Asset, error) {
	res, err := CreateResource(runtime, "alicloud.slb", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	lbs, err := res.(*mqlAlicloudSlb).loadBalancers()
	if err != nil {
		return nil, err
	}
	assets := make([]*inventory.Asset, 0, len(lbs))
	for _, il := range lbs {
		lb := il.(*mqlAlicloudSlbLoadBalancer)
		id := lb.LoadBalancerId.Data
		if id == "" {
			continue
		}
		assets = append(assets, newChildAsset(conf, conn.ID(), lb.RegionId.Data,
			connection.NewSlbIdentifier(id), connection.NewSlbPlatform(id),
			nameOr(lb.LoadBalancerName.Data, id), connection.OptionSlbID, id))
	}
	return assets, nil
}

func discoverRedisInstances(runtime *plugin.Runtime, conn *connection.AlicloudConnection, conf *inventory.Config) ([]*inventory.Asset, error) {
	res, err := CreateResource(runtime, "alicloud.redis", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	instances, err := res.(*mqlAlicloudRedis).instances()
	if err != nil {
		return nil, err
	}
	assets := make([]*inventory.Asset, 0, len(instances))
	for _, ii := range instances {
		inst := ii.(*mqlAlicloudRedisInstance)
		id := inst.InstanceId.Data
		if id == "" {
			continue
		}
		assets = append(assets, newChildAsset(conf, conn.ID(), inst.RegionId.Data,
			connection.NewRedisInstanceIdentifier(id), connection.NewRedisInstancePlatform(id),
			nameOr(inst.InstanceName.Data, id), connection.OptionRedisInstanceID, id))
	}
	return assets, nil
}

func discoverMongodbInstances(runtime *plugin.Runtime, conn *connection.AlicloudConnection, conf *inventory.Config) ([]*inventory.Asset, error) {
	res, err := CreateResource(runtime, "alicloud.mongodb", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	instances, err := res.(*mqlAlicloudMongodb).instances()
	if err != nil {
		return nil, err
	}
	assets := make([]*inventory.Asset, 0, len(instances))
	for _, ii := range instances {
		inst := ii.(*mqlAlicloudMongodbInstance)
		id := inst.DbInstanceId.Data
		if id == "" {
			continue
		}
		assets = append(assets, newChildAsset(conf, conn.ID(), inst.RegionId.Data,
			connection.NewMongodbInstanceIdentifier(id), connection.NewMongodbInstancePlatform(id),
			nameOr(inst.DbInstanceDescription.Data, id), connection.OptionMongodbInstanceID, id))
	}
	return assets, nil
}

func discoverPolardbClusters(runtime *plugin.Runtime, conn *connection.AlicloudConnection, conf *inventory.Config) ([]*inventory.Asset, error) {
	res, err := CreateResource(runtime, "alicloud.polardb", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	clusters, err := res.(*mqlAlicloudPolardb).clusters()
	if err != nil {
		return nil, err
	}
	assets := make([]*inventory.Asset, 0, len(clusters))
	for _, ic := range clusters {
		cluster := ic.(*mqlAlicloudPolardbCluster)
		id := cluster.DbClusterId.Data
		if id == "" {
			continue
		}
		assets = append(assets, newChildAsset(conf, conn.ID(), cluster.RegionId.Data,
			connection.NewPolardbClusterIdentifier(id), connection.NewPolardbClusterPlatform(id),
			nameOr(cluster.DbClusterDescription.Data, id), connection.OptionPolardbClusterID, id))
	}
	return assets, nil
}

func discoverFcFunctions(runtime *plugin.Runtime, conn *connection.AlicloudConnection, conf *inventory.Config) ([]*inventory.Asset, error) {
	res, err := CreateResource(runtime, "alicloud.fc", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	functions, err := res.(*mqlAlicloudFc).functions()
	if err != nil {
		return nil, err
	}
	assets := make([]*inventory.Asset, 0, len(functions))
	for _, ifn := range functions {
		fn := ifn.(*mqlAlicloudFcFunction)
		name := fn.FunctionName.Data
		region := fn.RegionId.Data
		if name == "" || region == "" {
			continue
		}
		assets = append(assets, newChildAsset(conf, conn.ID(), region,
			connection.NewFcFunctionIdentifier(region, name), connection.NewFcFunctionPlatform(region, name),
			name, connection.OptionFcFunctionName, name))
	}
	return assets, nil
}

func discoverAcrInstances(runtime *plugin.Runtime, conn *connection.AlicloudConnection, conf *inventory.Config) ([]*inventory.Asset, error) {
	res, err := CreateResource(runtime, "alicloud.acr", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	instances, err := res.(*mqlAlicloudAcr).instances()
	if err != nil {
		return nil, err
	}
	assets := make([]*inventory.Asset, 0, len(instances))
	for _, ii := range instances {
		inst := ii.(*mqlAlicloudAcrInstance)
		id := inst.InstanceId.Data
		if id == "" {
			continue
		}
		assets = append(assets, newChildAsset(conf, conn.ID(), inst.RegionId.Data,
			connection.NewAcrInstanceIdentifier(id), connection.NewAcrInstancePlatform(id),
			nameOr(inst.InstanceName.Data, id), connection.OptionAcrInstanceID, id))
	}
	return assets, nil
}

func discoverEsClusters(runtime *plugin.Runtime, conn *connection.AlicloudConnection, conf *inventory.Config) ([]*inventory.Asset, error) {
	res, err := CreateResource(runtime, "alicloud.es", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	instances, err := res.(*mqlAlicloudEs).instances()
	if err != nil {
		return nil, err
	}
	assets := make([]*inventory.Asset, 0, len(instances))
	for _, ii := range instances {
		inst := ii.(*mqlAlicloudEsInstance)
		id := inst.InstanceId.Data
		if id == "" {
			continue
		}
		assets = append(assets, newChildAsset(conf, conn.ID(), inst.RegionId.Data,
			connection.NewEsInstanceIdentifier(id), connection.NewEsInstancePlatform(id),
			nameOr(inst.Description.Data, id), connection.OptionEsInstanceID, id))
	}
	return assets, nil
}

func discoverWaf(runtime *plugin.Runtime, conn *connection.AlicloudConnection, conf *inventory.Config) ([]*inventory.Asset, error) {
	res, err := CreateResource(runtime, "alicloud.waf", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	instances, err := res.(*mqlAlicloudWaf).instances()
	if err != nil {
		return nil, err
	}
	assets := make([]*inventory.Asset, 0, len(instances))
	for _, ii := range instances {
		inst := ii.(*mqlAlicloudWafInstance)
		id := inst.InstanceId.Data
		if id == "" {
			continue
		}
		assets = append(assets, newChildAsset(conf, conn.ID(), inst.RegionId.Data,
			connection.NewWafInstanceIdentifier(id), connection.NewWafInstancePlatform(id),
			"WAF "+inst.RegionId.Data, connection.OptionWafInstanceID, id))
	}
	return assets, nil
}

func discoverCloudFirewall(runtime *plugin.Runtime, conn *connection.AlicloudConnection, conf *inventory.Config) ([]*inventory.Asset, error) {
	res, err := CreateResource(runtime, "alicloud.cloudFirewall", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	// Cloud Firewall is account-global; emit a single asset only when the
	// service is provisioned for the account (edition > 0).
	edition, err := res.(*mqlAlicloudCloudFirewall).edition()
	if err != nil {
		return nil, err
	}
	if edition == 0 {
		return nil, nil
	}
	// The account id is already cached on the connection from the detect step,
	// so this avoids a redundant STS call; fall back to Identify only if unset.
	accountID := conn.AccountID()
	if accountID == "" {
		accountID, err = conn.Identify()
		if err != nil {
			return nil, err
		}
	}
	// Cloud Firewall is a center service, so no region is stamped on the scope.
	asset := newChildAsset(conf, conn.ID(), "",
		connection.NewCloudFirewallIdentifier(accountID), connection.NewCloudFirewallPlatform(accountID),
		"Cloud Firewall "+accountID, connection.OptionCloudFirewall, accountID)
	return []*inventory.Asset{asset}, nil
}

// newChildAsset builds a discovered child asset with a scoped connection config.
func newChildAsset(conf *inventory.Config, parentID uint32, region, platformID string, platform *inventory.Platform, name, scopeKey, scopeValue string) *inventory.Asset {
	return &inventory.Asset{
		PlatformIds: []string{platformID},
		Name:        name,
		Platform:    platform,
		Labels:      map[string]string{},
		Connections: []*inventory.Config{scopedConfig(conf, parentID, region, scopeKey, scopeValue)},
	}
}

// nameOr returns name when non-empty, otherwise the fallback id.
func nameOr(name, fallback string) string {
	if name == "" {
		return fallback
	}
	return name
}

// scopedConfig clones the base connection config for a discovered child asset,
// disabling further discovery, recording the parent connection, narrowing the
// region fan-out to the object's region, and stamping the scope id so the child
// asset resolves to a single object.
func scopedConfig(conf *inventory.Config, parentID uint32, region, scopeKey, scopeValue string) *inventory.Config {
	clone := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(parentID))
	if clone.Options == nil {
		clone.Options = map[string]string{}
	}
	clone.Options[scopeKey] = scopeValue
	if region != "" {
		clone.Options[connection.OptionRegions] = region
	}
	return clone
}
