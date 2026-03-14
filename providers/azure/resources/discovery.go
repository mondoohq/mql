// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/azure/connection"
	"go.mondoo.com/mql/v13/utils/stringx"

	subscriptions "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
)

const (
	SubscriptionLabel  = "azure.mondoo.com/subscription"
	ResourceGroupLabel = "azure.mondoo.com/resourcegroup"

	LocationLabel = "mondoo.com/location"
	InstanceLabel = "mondoo.com/instance"

	DiscoveryAuto          = "auto"
	DiscoveryAll           = "all"
	DiscoverySubscriptions = "subscriptions"
	DiscoveryInstances     = "instances"
	// TODO: this probably needs some more work on the linking to its OS counterpart side
	DiscoveryInstancesApi            = "instances-api"
	DiscoverySqlServers              = "sql-servers"
	DiscoveryPostgresServers         = "postgres-servers"
	DiscoveryPostgresFlexibleServers = "postgres-flexible-servers"
	DiscoveryMySqlServers            = "mysql-servers"
	DiscoveryMySqlFlexibleServers    = "mysql-flexible-servers"
	DiscoveryAksClusters             = "aks-clusters"
	DiscoveryAppServiceApps          = "app-service-webapps"
	DiscoveryCacheRedis              = "cache-redis-instances"
	DiscoveryBatchAccounts           = "batch-accounts"
	DiscoveryStorageAccounts         = "storage-accounts"
	DiscoveryStorageContainers       = "storage-containers"
	DiscoveryKeyVaults               = "keyvaults-vaults"
	DiscoverySecurityGroups          = "security-groups"
	DiscoveryCosmosDb                = "cosmosdb"
	DiscoveryVirtualNetworks         = "virtual-networks"
)

var All = []string{
	DiscoverySubscriptions,
	DiscoveryInstances,
}

var Auto = []string{DiscoverySubscriptions}

func allDiscovery() []string {
	return append(All, AllAPIResources...)
}

var AllAPIResources = []string{
	DiscoveryInstancesApi,
	DiscoverySqlServers,
	DiscoveryPostgresServers,
	DiscoveryPostgresFlexibleServers,
	DiscoveryMySqlServers,
	DiscoveryMySqlFlexibleServers,
	DiscoveryAksClusters,
	DiscoveryAppServiceApps,
	DiscoveryCacheRedis,
	DiscoveryBatchAccounts,
	DiscoveryStorageAccounts,
	DiscoveryStorageContainers,
	DiscoveryKeyVaults,
	DiscoverySecurityGroups,
	DiscoveryCosmosDb,
	DiscoveryVirtualNetworks,
}

type azureObject struct {
	subscription string
	tenant       *string
	id           string
	location     string
	service      string
	objectType   string
}

type azureObjectPlatformInfo struct {
	title    string
	platform string
}

type mqlObject struct {
	name        string
	labels      map[string]string
	azureObject azureObject
}

type subWithConfig struct {
	sub  subscriptions.Subscription
	conf *inventory.Config
}

func MondooAzureInstanceID(instanceID string) string {
	return "//platformid.api.mondoo.app/runtime/azure" + instanceID
}

func getDiscoveryTargets(config *inventory.Config) []string {
	targets := config.Discover.Targets
	if len(targets) == 0 {
		return Auto
	}
	if stringx.ContainsAnyOf(targets, DiscoveryAll) {
		// return the All list + All Api Resources list
		return allDiscovery()
	}
	if stringx.ContainsAnyOf(targets, DiscoveryAuto) {
		for i, target := range targets {
			if target == DiscoveryAuto {
				// remove the auto keyword
				targets = slices.Delete(targets, i, i+1)
			}
		}
		// add in the required discovery targets
		return append(targets, Auto...)
	}
	// random assortment of targets
	return targets
}

func Discover(runtime *plugin.Runtime, rootConf *inventory.Config) (*inventory.Inventory, error) {
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	assets := []*inventory.Asset{}
	subsToInclude := rootConf.Options["subscriptions"]
	subsToExclude := rootConf.Options["subscriptions-exclude"]
	filter := connection.SubscriptionsFilter{}
	if len(subsToInclude) > 0 {
		filter.Include = strings.Split(subsToInclude, ",")
	}
	if len(subsToExclude) > 0 {
		filter.Exclude = strings.Split(subsToExclude, ",")
	}
	// note: we always need the subscriptions, either to return them as assets or discover resources inside the subs
	subs, err := discoverSubscriptions(conn, filter)
	if err != nil {
		return nil, err
	}

	subsWithConfigs := make([]subWithConfig, len(subs))
	for i := range subs {
		sub := subs[i]
		subsWithConfigs[i] = subWithConfig{sub: sub, conf: getSubConfig(conn.Conf, sub)}
	}

	targets := getDiscoveryTargets(rootConf)

	if stringx.ContainsAnyOf(targets, DiscoverySubscriptions) {
		// we've already discovered those, simply add them as assets
		for _, s := range subsWithConfigs {
			assets = append(assets, subToAsset(s))
		}
	}

	// FIXME: do not discover instances as OSes right now, only discover as API representations.
	if stringx.ContainsAnyOf(targets, DiscoveryInstances) {
		vms, err := discoverInstances(runtime, subsWithConfigs)
		if err != nil {
			return nil, err
		}
		assets = append(assets, vms...)
	}
	if stringx.ContainsAnyOf(targets, DiscoveryInstancesApi) {
		vms, err := discoverInstancesApi(runtime, subsWithConfigs)
		if err != nil {
			return nil, err
		}
		assets = append(assets, vms...)
	}
	if stringx.ContainsAnyOf(targets, DiscoverySqlServers) {
		sqlServers, err := discoverSqlServers(runtime, subsWithConfigs)
		if err != nil {
			return nil, err
		}
		assets = append(assets, sqlServers...)
	}
	if stringx.ContainsAnyOf(targets, DiscoveryMySqlServers) {
		mySqlServers, err := discoverMySqlServers(runtime, subsWithConfigs)
		if err != nil {
			return nil, err
		}
		assets = append(assets, mySqlServers...)
	}
	if stringx.ContainsAnyOf(targets, DiscoveryMySqlFlexibleServers) {
		flexibleServers, err := discoverMySqlFlexibleServers(runtime, subsWithConfigs)
		if err != nil {
			return nil, err
		}
		assets = append(assets, flexibleServers...)
	}

	if stringx.ContainsAnyOf(targets, DiscoveryPostgresServers) {
		postgresServers, err := discoverPostgresqlServers(runtime, subsWithConfigs)
		if err != nil {
			return nil, err
		}
		assets = append(assets, postgresServers...)
	}

	if stringx.ContainsAnyOf(targets, DiscoveryPostgresFlexibleServers) {
		flexibleServers, err := discoverPostgresqlFlexibleServers(runtime, subsWithConfigs)
		if err != nil {
			return nil, err
		}
		assets = append(assets, flexibleServers...)
	}

	if stringx.ContainsAnyOf(targets, DiscoveryAksClusters) {
		aksClusters, err := discoverAksClusters(runtime, subsWithConfigs)
		if err != nil {
			return nil, err
		}
		assets = append(assets, aksClusters...)
	}

	if stringx.ContainsAnyOf(targets, DiscoveryAppServiceApps) {
		appServiceApps, err := discoverAppServiceApps(runtime, subsWithConfigs)
		if err != nil {
			return nil, err
		}
		assets = append(assets, appServiceApps...)
	}

	if stringx.ContainsAnyOf(targets, DiscoveryCacheRedis) {
		redisInstances, err := discoverCacheRedis(runtime, subsWithConfigs)
		if err != nil {
			return nil, err
		}
		assets = append(assets, redisInstances...)
	}

	if stringx.ContainsAnyOf(targets, DiscoveryBatchAccounts) {
		batchAccounts, err := discoverBatchAccounts(runtime, subsWithConfigs)
		if err != nil {
			return nil, err
		}
		assets = append(assets, batchAccounts...)
	}

	if stringx.ContainsAnyOf(targets, DiscoveryStorageAccounts) {
		accs, err := discoverStorageAccounts(runtime, subsWithConfigs)
		if err != nil {
			return nil, err
		}
		assets = append(assets, accs...)
	}

	// FIXME: bring back the storage containers as as part of FF scanning once we can do parallel scanning
	if stringx.ContainsAnyOf(targets, DiscoveryStorageContainers) {
		containers, err := discoverStorageAccountsContainers(runtime, subsWithConfigs)
		if err != nil {
			return nil, err
		}
		assets = append(assets, containers...)
	}

	if stringx.ContainsAnyOf(targets, DiscoverySecurityGroups) {
		secGrps, err := discoverSecurityGroups(runtime, subsWithConfigs)
		if err != nil {
			return nil, err
		}
		assets = append(assets, secGrps...)
	}

	if stringx.ContainsAnyOf(targets, DiscoveryKeyVaults) {
		kvs, err := discoverVaults(runtime, subsWithConfigs)
		if err != nil {
			return nil, err
		}
		assets = append(assets, kvs...)
	}

	if stringx.ContainsAnyOf(targets, DiscoveryCosmosDb) {
		cosmosDbAccounts, err := discoverCosmosDb(runtime, subsWithConfigs)
		if err != nil {
			return nil, err
		}
		assets = append(assets, cosmosDbAccounts...)
	}

	if stringx.ContainsAnyOf(targets, DiscoveryVirtualNetworks) {
		vnets, err := discoverVirtualNetworks(runtime, subsWithConfigs)
		if err != nil {
			return nil, err
		}
		assets = append(assets, vnets...)
	}

	return &inventory.Inventory{
		Spec: &inventory.InventorySpec{
			Assets: assets,
		},
	}, nil
}

func discoverInstancesApi(runtime *plugin.Runtime, subsWithConfigs []subWithConfig) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfigs {
		svc, err := NewResource(runtime, "azure.subscription.computeService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		computeSvc := svc.(*mqlAzureSubscriptionComputeService)
		vms := computeSvc.GetVms()
		if vms.Error != nil {
			return nil, vms.Error
		}
		for _, v := range vms.Data {
			vm := v.(*mqlAzureSubscriptionComputeServiceVm)
			props := vm.GetProperties()
			if props.Error != nil {
				return nil, props.Error
			}
			asset := mqlObjectToAsset(mqlObject{
				name:   vm.Name.Data,
				labels: interfaceMapToStr(vm.Tags.Data),
				azureObject: azureObject{
					id:           vm.Id.Data,
					subscription: *subWithConfig.sub.SubscriptionID,
					tenant:       subWithConfig.sub.TenantID,
					location:     vm.Location.Data,
					service:      "compute",
					objectType:   "vm-api",
				},
			}, subWithConfig.conf, false)
			labels, err := getInstancesLabels(vm)
			if err != nil {
				return nil, err
			}
			enrichWithLabels(asset, labels)
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func discoverInstances(runtime *plugin.Runtime, subsWithConfigs []subWithConfig) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfigs {
		svc, err := NewResource(runtime, "azure.subscription.computeService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		computeSvc := svc.(*mqlAzureSubscriptionComputeService)
		vms := computeSvc.GetVms()
		if vms.Error != nil {
			return nil, vms.Error
		}
		for _, v := range vms.Data {
			vm := v.(*mqlAzureSubscriptionComputeServiceVm)
			props := vm.GetProperties()
			if props.Error != nil {
				return nil, props.Error
			}

			ipAddresses := vm.GetPublicIpAddresses()
			if ipAddresses.Error != nil {
				return nil, ipAddresses.Error
			}
			asset := mqlObjectToAsset(mqlObject{
				name:   vm.Name.Data,
				labels: interfaceMapToStr(vm.Tags.Data),
				azureObject: azureObject{
					id:           vm.Id.Data,
					subscription: *subWithConfig.sub.SubscriptionID,
					tenant:       subWithConfig.sub.TenantID,
					location:     vm.Location.Data,
					service:      "compute",
					objectType:   "vm",
				},
			}, subWithConfig.conf, false)
			for _, ip := range ipAddresses.Data {
				ipAddress := ip.(*mqlAzureSubscriptionNetworkServiceIpAddress)
				// TODO: we need to make this work via another provider maybe?
				// this is the OS representation of the VM itself
				asset.Connections = append(asset.Connections, &inventory.Config{
					Type:     "ssh",
					Host:     ipAddress.IpAddress.Data,
					Insecure: true,
				})
			}
			labels, err := getInstancesLabels(vm)
			if err != nil {
				return nil, err
			}
			enrichWithLabels(asset, labels)
			asset.PlatformIds = []string{MondooAzureInstanceID(vm.Id.Data)}
			asset.Platform.Runtime = "azure"
			asset.Platform.Kind = inventory.AssetKindCloudVM
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func discoverSqlServers(runtime *plugin.Runtime, subsWithConfigs []subWithConfig) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfigs {
		svc, err := NewResource(runtime, "azure.subscription.sqlService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		sqlSvc := svc.(*mqlAzureSubscriptionSqlService)
		servers := sqlSvc.GetServers()
		if servers.Error != nil {
			return nil, servers.Error
		}
		for _, sqlServ := range servers.Data {
			s := sqlServ.(*mqlAzureSubscriptionSqlServiceServer)
			asset := mqlObjectToAsset(mqlObject{
				name:   s.Name.Data,
				labels: interfaceMapToStr(s.Tags.Data),
				azureObject: azureObject{
					id:           s.Id.Data,
					subscription: *subWithConfig.sub.SubscriptionID,
					tenant:       subWithConfig.sub.TenantID,
					location:     s.Location.Data,
					service:      "sql",
					objectType:   "server",
				},
			}, subWithConfig.conf, false)
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func discoverMySqlServers(runtime *plugin.Runtime, subsWithConfigs []subWithConfig) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfigs {
		svc, err := NewResource(runtime, "azure.subscription.mySqlService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		mysqlSvc := svc.(*mqlAzureSubscriptionMySqlService)
		servers := mysqlSvc.GetServers()
		if servers.Error != nil {
			return nil, servers.Error
		}
		for _, mysqlServ := range servers.Data {
			s := mysqlServ.(*mqlAzureSubscriptionMySqlServiceServer)
			asset := mqlObjectToAsset(mqlObject{
				name:   s.Name.Data,
				labels: interfaceMapToStr(s.Tags.Data),
				azureObject: azureObject{
					id:           s.Id.Data,
					subscription: *subWithConfig.sub.SubscriptionID,
					tenant:       subWithConfig.sub.TenantID,
					location:     s.Location.Data,
					service:      "mysql",
					objectType:   "server",
				},
			}, subWithConfig.conf, false)
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func discoverMySqlFlexibleServers(runtime *plugin.Runtime, subsWithConfigs []subWithConfig) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfigs {
		svc, err := NewResource(runtime, "azure.subscription.mySqlService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		mysqlSvc := svc.(*mqlAzureSubscriptionMySqlService)
		servers := mysqlSvc.GetFlexibleServers()
		if servers.Error != nil {
			return nil, servers.Error
		}
		for _, mysqlServ := range servers.Data {
			s := mysqlServ.(*mqlAzureSubscriptionMySqlServiceFlexibleServer)
			asset := mqlObjectToAsset(mqlObject{
				name:   s.Name.Data,
				labels: interfaceMapToStr(s.Tags.Data),
				azureObject: azureObject{
					id:           s.Id.Data,
					subscription: *subWithConfig.sub.SubscriptionID,
					tenant:       subWithConfig.sub.TenantID,
					location:     s.Location.Data,
					service:      "mysql",
					objectType:   "flexible-server",
				},
			}, subWithConfig.conf, false)
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func discoverPostgresqlServers(runtime *plugin.Runtime, subsWithConfigs []subWithConfig) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfigs {
		svc, err := NewResource(runtime, "azure.subscription.postgreSqlService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		postgresSvc := svc.(*mqlAzureSubscriptionPostgreSqlService)
		servers := postgresSvc.GetServers()
		if servers.Error != nil {
			return nil, servers.Error
		}
		for _, mysqlServ := range servers.Data {
			s := mysqlServ.(*mqlAzureSubscriptionPostgreSqlServiceServer)
			asset := mqlObjectToAsset(mqlObject{
				name:   s.Name.Data,
				labels: interfaceMapToStr(s.Tags.Data),
				azureObject: azureObject{
					id:           s.Id.Data,
					subscription: *subWithConfig.sub.SubscriptionID,
					tenant:       subWithConfig.sub.TenantID,
					location:     s.Location.Data,
					service:      "postgresql",
					objectType:   "server",
				},
			}, subWithConfig.conf, false)
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func discoverPostgresqlFlexibleServers(runtime *plugin.Runtime, subsWithConfigs []subWithConfig) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfigs {
		svc, err := NewResource(runtime, "azure.subscription.postgreSqlService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		postgresSvc := svc.(*mqlAzureSubscriptionPostgreSqlService)
		servers := postgresSvc.GetFlexibleServers()
		if servers.Error != nil {
			return nil, servers.Error
		}
		for _, mysqlServ := range servers.Data {
			s := mysqlServ.(*mqlAzureSubscriptionPostgreSqlServiceFlexibleServer)
			asset := mqlObjectToAsset(mqlObject{
				name:   s.Name.Data,
				labels: interfaceMapToStr(s.Tags.Data),
				azureObject: azureObject{
					id:           s.Id.Data,
					subscription: *subWithConfig.sub.SubscriptionID,
					tenant:       subWithConfig.sub.TenantID,
					location:     s.Location.Data,
					service:      "postgresql",
					objectType:   "flexible-server",
				},
			}, subWithConfig.conf, false)
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func discoverAksClusters(runtime *plugin.Runtime, subsWithConfigs []subWithConfig) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfigs {
		svc, err := NewResource(runtime, "azure.subscription.aksService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		aksSvc := svc.(*mqlAzureSubscriptionAksService)
		clusters := aksSvc.GetClusters()
		if clusters.Error != nil {
			return nil, clusters.Error
		}
		for _, c := range clusters.Data {
			cluster := c.(*mqlAzureSubscriptionAksServiceCluster)
			asset := mqlObjectToAsset(mqlObject{
				name:   cluster.Name.Data,
				labels: interfaceMapToStr(cluster.Tags.Data),
				azureObject: azureObject{
					id:           cluster.Id.Data,
					subscription: *subWithConfig.sub.SubscriptionID,
					tenant:       subWithConfig.sub.TenantID,
					location:     cluster.Location.Data,
					service:      "aks",
					objectType:   "cluster",
				},
			}, subWithConfig.conf, false)
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func discoverAppServiceApps(runtime *plugin.Runtime, subsWithConfigs []subWithConfig) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfigs {
		svc, err := NewResource(runtime, "azure.subscription.webService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		webSvc := svc.(*mqlAzureSubscriptionWebService)
		apps := webSvc.GetApps()
		if apps.Error != nil {
			return nil, apps.Error
		}
		for _, a := range apps.Data {
			app := a.(*mqlAzureSubscriptionWebServiceAppsite)
			asset := mqlObjectToAsset(mqlObject{
				name:   app.Name.Data,
				labels: interfaceMapToStr(app.Tags.Data),
				azureObject: azureObject{
					id:           app.Id.Data,
					subscription: *subWithConfig.sub.SubscriptionID,
					tenant:       subWithConfig.sub.TenantID,
					location:     app.Location.Data,
					service:      "app-service",
					objectType:   "app",
				},
			}, subWithConfig.conf, false)
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func discoverCacheRedis(runtime *plugin.Runtime, subsWithConfigs []subWithConfig) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfigs {
		svc, err := NewResource(runtime, "azure.subscription.cacheService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		cacheSvc := svc.(*mqlAzureSubscriptionCacheService)
		redisInstances := cacheSvc.GetRedis()
		if redisInstances.Error != nil {
			return nil, redisInstances.Error
		}
		for _, r := range redisInstances.Data {
			instance := r.(*mqlAzureSubscriptionCacheServiceRedisInstance)
			asset := mqlObjectToAsset(mqlObject{
				name:   instance.Name.Data,
				labels: interfaceMapToStr(instance.Tags.Data),
				azureObject: azureObject{
					id:           instance.Id.Data,
					subscription: *subWithConfig.sub.SubscriptionID,
					tenant:       subWithConfig.sub.TenantID,
					location:     instance.Location.Data,
					service:      "cache",
					objectType:   "redis",
				},
			}, subWithConfig.conf, false)
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func discoverBatchAccounts(runtime *plugin.Runtime, subsWithConfigs []subWithConfig) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfigs {
		svc, err := NewResource(runtime, "azure.subscription.batchService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		batchSvc := svc.(*mqlAzureSubscriptionBatchService)
		accounts := batchSvc.GetAccounts()
		if accounts.Error != nil {
			return nil, accounts.Error
		}
		for _, a := range accounts.Data {
			account := a.(*mqlAzureSubscriptionBatchServiceAccount)
			asset := mqlObjectToAsset(mqlObject{
				name:   account.Name.Data,
				labels: interfaceMapToStr(account.Tags.Data),
				azureObject: azureObject{
					id:           account.Id.Data,
					subscription: *subWithConfig.sub.SubscriptionID,
					tenant:       subWithConfig.sub.TenantID,
					location:     account.Location.Data,
					service:      "batch",
					objectType:   "account",
				},
			}, subWithConfig.conf, false)
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func discoverCosmosDb(runtime *plugin.Runtime, subsWithConfigs []subWithConfig) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfigs {
		svc, err := NewResource(runtime, "azure.subscription.cosmosDbService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		cosmosDbSvc := svc.(*mqlAzureSubscriptionCosmosDbService)
		accounts := cosmosDbSvc.GetAccounts()
		if accounts.Error != nil {
			return nil, accounts.Error
		}
		for _, a := range accounts.Data {
			account := a.(*mqlAzureSubscriptionCosmosDbServiceAccount)
			asset := mqlObjectToAsset(mqlObject{
				name:   account.Name.Data,
				labels: interfaceMapToStr(account.Tags.Data),
				azureObject: azureObject{
					id:           account.Id.Data,
					subscription: *subWithConfig.sub.SubscriptionID,
					tenant:       subWithConfig.sub.TenantID,
					location:     account.Location.Data,
					service:      "cosmosdb",
					objectType:   "account",
				},
			}, subWithConfig.conf, false)
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func discoverStorageAccounts(runtime *plugin.Runtime, subsWithConfig []subWithConfig) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfig {
		svc, err := NewResource(runtime, "azure.subscription.storageService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		storageSvc := svc.(*mqlAzureSubscriptionStorageService)
		accounts := storageSvc.GetAccounts()
		if accounts.Error != nil {
			return nil, accounts.Error
		}
		for _, account := range accounts.Data {
			a := account.(*mqlAzureSubscriptionStorageServiceAccount)
			asset := mqlObjectToAsset(mqlObject{
				name:   a.Name.Data,
				labels: interfaceMapToStr(a.Tags.Data),
				azureObject: azureObject{
					id:           a.Id.Data,
					subscription: *subWithConfig.sub.SubscriptionID,
					tenant:       subWithConfig.sub.TenantID,
					location:     a.Location.Data,
					service:      "storage",
					objectType:   "account",
				},
			}, subWithConfig.conf, true)
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func discoverStorageAccountsContainers(runtime *plugin.Runtime, subsWithConfig []subWithConfig) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfig {
		svc, err := NewResource(runtime, "azure.subscription.storageService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		storageSvc := svc.(*mqlAzureSubscriptionStorageService)
		accounts := storageSvc.GetAccounts()
		if accounts.Error != nil {
			return nil, accounts.Error
		}
		for _, account := range accounts.Data {
			a := account.(*mqlAzureSubscriptionStorageServiceAccount)
			containers := a.GetContainers()
			if containers.Error != nil {
				return nil, containers.Error
			}
			for _, container := range containers.Data {
				c := container.(*mqlAzureSubscriptionStorageServiceAccountContainer)
				asset := mqlObjectToAsset(mqlObject{
					name:   c.Name.Data,
					labels: map[string]string{},
					azureObject: azureObject{
						id:           c.Id.Data,
						subscription: *subWithConfig.sub.SubscriptionID,
						tenant:       subWithConfig.sub.TenantID,
						location:     a.Location.Data,
						service:      "storage",
						objectType:   "container",
					},
				}, subWithConfig.conf, true)
				assets = append(assets, asset)
			}
		}
	}
	return assets, nil
}

func discoverSecurityGroups(runtime *plugin.Runtime, subsWithConfigs []subWithConfig) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfigs {
		svc, err := NewResource(runtime, "azure.subscription.networkService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		networkSvc := svc.(*mqlAzureSubscriptionNetworkService)
		secGrps := networkSvc.GetSecurityGroups()
		if secGrps.Error != nil {
			return nil, secGrps.Error
		}
		for _, secGrp := range secGrps.Data {
			s := secGrp.(*mqlAzureSubscriptionNetworkServiceSecurityGroup)
			asset := mqlObjectToAsset(mqlObject{
				name:   s.Name.Data,
				labels: interfaceMapToStr(s.Tags.Data),
				azureObject: azureObject{
					id:           s.Id.Data,
					subscription: *subWithConfig.sub.SubscriptionID,
					tenant:       subWithConfig.sub.TenantID,
					location:     s.Location.Data,
					service:      "network",
					objectType:   "security-group",
				},
			}, subWithConfig.conf, true)
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func discoverVirtualNetworks(runtime *plugin.Runtime, subsWithConfigs []subWithConfig) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfigs {
		svc, err := NewResource(runtime, "azure.subscription.networkService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		networkSvc := svc.(*mqlAzureSubscriptionNetworkService)
		vnets := networkSvc.GetVirtualNetworks()
		if vnets.Error != nil {
			return nil, vnets.Error
		}
		for _, vnet := range vnets.Data {
			v := vnet.(*mqlAzureSubscriptionNetworkServiceVirtualNetwork)
			asset := mqlObjectToAsset(mqlObject{
				name:   v.Name.Data,
				labels: interfaceMapToStr(v.Tags.Data),
				azureObject: azureObject{
					id:           v.Id.Data,
					subscription: *subWithConfig.sub.SubscriptionID,
					tenant:       subWithConfig.sub.TenantID,
					location:     v.Location.Data,
					service:      "network",
					objectType:   "virtual-network",
				},
			}, subWithConfig.conf, true)
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func discoverVaults(runtime *plugin.Runtime, subsWithConfigs []subWithConfig) ([]*inventory.Asset, error) {
	assets := []*inventory.Asset{}
	for _, subWithConfig := range subsWithConfigs {
		svc, err := NewResource(runtime, "azure.subscription.keyVaultService", map[string]*llx.RawData{
			"subscriptionId": llx.StringDataPtr(subWithConfig.sub.SubscriptionID),
		})
		if err != nil {
			return nil, err
		}
		kvSvc := svc.(*mqlAzureSubscriptionKeyVaultService)
		vaults := kvSvc.GetVaults()
		if vaults.Error != nil {
			return nil, vaults.Error
		}
		for _, vlt := range vaults.Data {
			v := vlt.(*mqlAzureSubscriptionKeyVaultServiceVault)
			asset := mqlObjectToAsset(mqlObject{
				name:   v.VaultName.Data,
				labels: interfaceMapToStr(v.Tags.Data),
				azureObject: azureObject{
					id:           v.Id.Data,
					subscription: *subWithConfig.sub.SubscriptionID,
					tenant:       subWithConfig.sub.TenantID,
					location:     v.Location.Data,
					service:      "keyvault",
					objectType:   "vault",
				},
			}, subWithConfig.conf, false)
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func AzureObjectPlatformId(id string) string {
	// the azure resources have an unique id (even throughout multiple subscriptions), e.g.
	// /subscriptions/f1a2873a-6b27-4097-aa7c-3df51f103e96/resourceGroups/MS365-CIS/providers/Microsoft.Compute/virtualMachines/ms365-windows
	// that should be enough for an unique platform id
	return "//platformid.api.mondoo.app/runtime/azure/v1" + id
}

func enrichWithLabels(a *inventory.Asset, labels map[string]string) {
	if a.Labels == nil {
		a.Labels = map[string]string{}
	}
	for k, v := range labels {
		a.Labels[k] = v
	}
}

func getInstancesLabels(vm *mqlAzureSubscriptionComputeServiceVm) (map[string]string, error) {
	labels := map[string]string{}
	props := vm.GetProperties()
	if props.Error != nil {
		return nil, props.Error
	}

	propsDict := props.Data.(map[string]any)
	osProfile, ok := propsDict["osProfile"]
	if ok {
		if osProfileDict, ok := osProfile.(map[string]any); ok {
			labels["azure.mondoo.com/computername"] = osProfileDict["computerName"].(string)
		}
	}
	storageProfile, ok := propsDict["storageProfile"]
	if ok {
		if storageProfile, ok := storageProfile.(map[string]any); ok {
			osDisk, ok := storageProfile["osDisk"]
			if ok {
				if osDisk, ok := osDisk.(map[string]any); ok {
					if osType, ok := osDisk["osType"]; ok {
						labels["azure.mondoo.com/ostype"] = osType.(string)
					}
				}
			}
		}
	}
	vmId, ok := propsDict["vmId"]
	if ok {
		if casted, ok := vmId.(string); ok {
			labels["mondoo.com/instance"] = casted
		}
	}

	res, err := ParseResourceID(vm.Id.Data)
	if err != nil {
		return nil, err
	}
	labels["azure.mondoo.com/resourcegroup"] = res.ResourceGroup

	return labels, nil
}

func discoverSubscriptions(conn *connection.AzureConnection, filter connection.SubscriptionsFilter) ([]subscriptions.Subscription, error) {
	subsClient := connection.NewSubscriptionsClient(conn.Token(), conn.ClientOptions())
	subs, err := subsClient.GetSubscriptions(filter)
	if err != nil {
		return nil, err
	}
	if len(subs) == 0 {
		return nil, errors.New("cannot find an azure subscription with the provided credentials or the provided filters")
	}

	return subs, nil
}

func subToAsset(subWithConfig subWithConfig) *inventory.Asset {
	sub := subWithConfig.sub
	conf := subWithConfig.conf
	copyConf := conf.Clone(inventory.WithoutDiscovery())
	platformId := "//platformid.api.mondoo.app/runtime/azure/subscriptions/" + *sub.SubscriptionID
	tenantId := "unknown"
	if sub.TenantID != nil {
		tenantId = *sub.TenantID
	}
	return &inventory.Asset{
		Id: platformId,
		Platform: &inventory.Platform{
			Title:                 "Azure Subscription",
			Name:                  "azure",
			Runtime:               "azure",
			Kind:                  "api",
			TechnologyUrlSegments: []string{"azure", tenantId, *sub.SubscriptionID, "account"},
		},
		Name:        fmt.Sprintf("Azure subscription %s", *sub.DisplayName),
		Connections: []*inventory.Config{copyConf},
		PlatformIds: []string{platformId},
	}
}

// creates a config with filled in subscription and tenant id, this config can be used by the subscription asset
// or any assets that are discovered within that subscription
func getSubConfig(rootConf *inventory.Config, sub subscriptions.Subscription) *inventory.Config {
	cfg := rootConf.Clone(inventory.WithoutDiscovery())
	if cfg.Options == nil {
		cfg.Options = map[string]string{}
	}
	cfg.Options[connection.OptionSubscriptionID] = *sub.SubscriptionID
	if sub.TenantID != nil {
		cfg.Options[connection.OptionTenantID] = *sub.TenantID
	}
	return cfg
}

func getTitleFamily(azureObject azureObject) (azureObjectPlatformInfo, error) {
	switch azureObject.service {
	case "compute":
		if azureObject.objectType == "vm" {
			return azureObjectPlatformInfo{title: "Azure Compute VM", platform: "azure-compute-vm"}, nil
		}
		if azureObject.objectType == "vm-api" {
			return azureObjectPlatformInfo{title: "Azure Compute VM", platform: "azure-compute-vm-api"}, nil
		}
	case "sql":
		if azureObject.objectType == "server" {
			return azureObjectPlatformInfo{title: "Azure SQL Database Server", platform: "azure-sql-server"}, nil
		}
	case "postgresql":
		if azureObject.objectType == "server" {
			return azureObjectPlatformInfo{title: "Azure PostgreSQL Server", platform: "azure-postgresql-server"}, nil
		}
		if azureObject.objectType == "flexible-server" {
			return azureObjectPlatformInfo{title: "Azure PostgreSQL Flexible Server", platform: "azure-postgresql-flexible-server"}, nil
		}
	case "mysql":
		if azureObject.objectType == "server" {
			return azureObjectPlatformInfo{title: "Azure MySQL Server", platform: "azure-mysql-server"}, nil
		}
		if azureObject.objectType == "flexible-server" {
			return azureObjectPlatformInfo{title: "Azure MySQL Flexible Server", platform: "azure-mysql-flexible-server"}, nil
		}
	case "aks":
		if azureObject.objectType == "cluster" {
			return azureObjectPlatformInfo{title: "Azure AKS Cluster", platform: "azure-aks-cluster"}, nil
		}
	case "app-service":
		if azureObject.objectType == "app" {
			return azureObjectPlatformInfo{title: "Azure App Service App", platform: "azure-app-service-webapp"}, nil
		}
	case "cache":
		if azureObject.objectType == "redis" {
			return azureObjectPlatformInfo{title: "Azure Cache for Redis Instance", platform: "azure-cache-redis-instance"}, nil
		}
	case "batch":
		if azureObject.objectType == "account" {
			return azureObjectPlatformInfo{title: "Azure Batch Account", platform: "azure-batch-account"}, nil
		}
	case "storage":
		if azureObject.objectType == "account" {
			return azureObjectPlatformInfo{title: "Azure Storage Account", platform: "azure-storage-account"}, nil
		}
		if azureObject.objectType == "container" {
			return azureObjectPlatformInfo{title: "Azure Storage Account Container", platform: "azure-storage-container"}, nil
		}
	case "network":
		if azureObject.objectType == "security-group" {
			return azureObjectPlatformInfo{title: "Azure Network Security Group", platform: "azure-network-security-group"}, nil
		}
		if azureObject.objectType == "virtual-network" {
			return azureObjectPlatformInfo{title: "Azure Virtual Network", platform: "azure-virtual-network"}, nil
		}
	case "keyvault":
		if azureObject.objectType == "vault" {
			return azureObjectPlatformInfo{title: "Azure Key Vault", platform: "azure-keyvault-vault"}, nil
		}
	case "cosmosdb":
		if azureObject.objectType == "account" {
			return azureObjectPlatformInfo{title: "Azure Cosmos DB Account", platform: "azure-cosmosdb"}, nil
		}
	}
	return azureObjectPlatformInfo{}, fmt.Errorf("missing runtime info for azure object service %s type %s", azureObject.service, azureObject.objectType)
}

func mqlObjectToAsset(mqlObject mqlObject, parentConf *inventory.Config, includeObjectTypeInUrl bool) *inventory.Asset {
	if mqlObject.name == "" {
		mqlObject.name = mqlObject.azureObject.id
	}
	info, err := getTitleFamily(mqlObject.azureObject)
	if err != nil {
		return nil
	}
	platformid := AzureObjectPlatformId(mqlObject.azureObject.id)
	cfg := parentConf.Clone(inventory.WithoutDiscovery())
	cfg.PlatformId = platformid

	tenantId := "unknown"
	if mqlObject.azureObject.tenant != nil {
		tenantId = *mqlObject.azureObject.tenant
	}

	assetUrl := []string{
		"azure", tenantId, mqlObject.azureObject.subscription,
		mqlObject.azureObject.service,
	}
	if includeObjectTypeInUrl {
		assetUrl = append(assetUrl, mqlObject.azureObject.objectType)
	}
	return &inventory.Asset{
		PlatformIds: []string{platformid, mqlObject.azureObject.id},
		Name:        mqlObject.name,
		Platform: &inventory.Platform{
			Name:                  info.platform,
			Title:                 info.title,
			Kind:                  "azure-object",
			Runtime:               "azure",
			TechnologyUrlSegments: assetUrl,
		},
		State:       inventory.State_STATE_ONLINE,
		Labels:      addInformationalLabels(mqlObject.labels, mqlObject),
		Connections: []*inventory.Config{cfg},
	}
}

func addInformationalLabels(l map[string]string, o mqlObject) map[string]string {
	if l == nil {
		l = make(map[string]string)
	}
	l[LocationLabel] = o.azureObject.location
	l[SubscriptionLabel] = o.azureObject.subscription
	resourceID, err := ParseResourceID(o.azureObject.id)
	if err == nil {
		l[ResourceGroupLabel] = resourceID.ResourceGroup
	}
	return l
}

func interfaceMapToStr(m map[string]any) map[string]string {
	res := make(map[string]string)
	for k, v := range m {
		if str, ok := v.(string); ok {
			res[k] = str
		}
	}
	return res
}
