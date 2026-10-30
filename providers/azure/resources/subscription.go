// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func initAzureSubscription(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	azure, err := CreateResource(runtime, "azure", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	az := azure.(*mqlAzure)
	if az.sub != nil {
		return nil, az.sub, nil
	}

	// Cached on the connection: asset detection already fetched this record
	// when it named the root asset, so the common case costs no API call.
	resp, err := conn.Subscription()
	if err != nil {
		return nil, nil, err
	}

	managedByTenants := []any{}
	for _, t := range resp.ManagedByTenants {
		if t != nil {
			managedByTenants = append(managedByTenants, *t.TenantID)
		}
	}
	subPolicies, err := convert.JsonToDict(resp.SubscriptionPolicies)
	if err != nil {
		return nil, nil, err
	}
	args["id"] = llx.StringDataPtr(resp.ID)
	args["name"] = llx.StringDataPtr(resp.DisplayName)
	args["tenantId"] = llx.StringDataPtr(resp.TenantID)
	args["tags"] = llx.MapData(convert.PtrMapStrToInterface(resp.Tags), types.String)
	args["state"] = llx.StringDataPtr((*string)(resp.State))
	args["subscriptionId"] = llx.StringDataPtr(resp.SubscriptionID)
	args["authorizationSource"] = llx.StringDataPtr((*string)(resp.AuthorizationSource))
	args["managedByTenants"] = llx.ArrayData(managedByTenants, types.String)
	args["subscriptionsPolicies"] = llx.DictData(subPolicies)
	sub, err := CreateResource(runtime, "azure.subscription", args)
	if err != nil {
		return nil, nil, err
	}
	az.sub = sub.(*mqlAzureSubscription)
	return nil, az.sub, nil
}

func (a *mqlAzureSubscription) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscription) compute() (*mqlAzureSubscriptionComputeService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionComputeService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	computeSvc := svc.(*mqlAzureSubscriptionComputeService)
	return computeSvc, nil
}

func (a *mqlAzureSubscription) batch() (*mqlAzureSubscriptionBatchService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionBatchService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	batchSvc := svc.(*mqlAzureSubscriptionBatchService)
	return batchSvc, nil
}

func (a *mqlAzureSubscription) databricks() (*mqlAzureSubscriptionDatabricksService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionDatabricksService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	databricksSvc := svc.(*mqlAzureSubscriptionDatabricksService)
	return databricksSvc, nil
}

func (a *mqlAzureSubscription) network() (*mqlAzureSubscriptionNetworkService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	networkSvc := svc.(*mqlAzureSubscriptionNetworkService)
	return networkSvc, nil
}

func (a *mqlAzureSubscription) storage() (*mqlAzureSubscriptionStorageService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionStorageService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	storageSvc := svc.(*mqlAzureSubscriptionStorageService)
	return storageSvc, nil
}

func (a *mqlAzureSubscription) web() (*mqlAzureSubscriptionWebService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionWebService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	webSvc := svc.(*mqlAzureSubscriptionWebService)
	return webSvc, nil
}

func (a *mqlAzureSubscription) sql() (*mqlAzureSubscriptionSqlService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionSqlService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	sqlSvc := svc.(*mqlAzureSubscriptionSqlService)
	return sqlSvc, nil
}

func (a *mqlAzureSubscription) mySql() (*mqlAzureSubscriptionMySqlService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionMySqlService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	mySqlSvc := svc.(*mqlAzureSubscriptionMySqlService)
	return mySqlSvc, nil
}

func (a *mqlAzureSubscription) postgreSql() (*mqlAzureSubscriptionPostgreSqlService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionPostgreSqlService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	postgreSqlSvc := svc.(*mqlAzureSubscriptionPostgreSqlService)
	return postgreSqlSvc, nil
}

func (a *mqlAzureSubscription) cosmosDb() (*mqlAzureSubscriptionCosmosDbService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionCosmosDbService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	cosmosDbSvc := svc.(*mqlAzureSubscriptionCosmosDbService)
	return cosmosDbSvc, nil
}

func (a *mqlAzureSubscription) keyVault() (*mqlAzureSubscriptionKeyVaultService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionKeyVaultService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	kvSvc := svc.(*mqlAzureSubscriptionKeyVaultService)
	return kvSvc, nil
}

func (a *mqlAzureSubscription) cloudDefender() (*mqlAzureSubscriptionCloudDefenderService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionCloudDefenderService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	cdSvc := svc.(*mqlAzureSubscriptionCloudDefenderService)
	return cdSvc, nil
}

func (a *mqlAzureSubscription) aks() (*mqlAzureSubscriptionAksService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionAksService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	aksSvc := svc.(*mqlAzureSubscriptionAksService)
	return aksSvc, nil
}

func (a *mqlAzureSubscription) monitor() (*mqlAzureSubscriptionMonitorService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionMonitorService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	monitorSvc := svc.(*mqlAzureSubscriptionMonitorService)
	return monitorSvc, nil
}

func (a *mqlAzureSubscription) advisor() (*mqlAzureSubscriptionAdvisorService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionAdvisorService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	advisorSvc := svc.(*mqlAzureSubscriptionAdvisorService)
	return advisorSvc, nil
}

func (a *mqlAzureSubscription) policy() (*mqlAzureSubscriptionPolicy, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionPolicy, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	policySvc := svc.(*mqlAzureSubscriptionPolicy)
	return policySvc, nil
}

func (a *mqlAzureSubscription) iot() (*mqlAzureSubscriptionIotService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionIotService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	iotSvc := svc.(*mqlAzureSubscriptionIotService)
	return iotSvc, nil
}

func (a *mqlAzureSubscription) cache() (*mqlAzureSubscriptionCacheService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionCacheService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	cacheSvc := svc.(*mqlAzureSubscriptionCacheService)
	return cacheSvc, nil
}

func (a *mqlAzureSubscription) dataFactory() (*mqlAzureSubscriptionDataFactoryService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionDataFactoryService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	dataFactorySvc := svc.(*mqlAzureSubscriptionDataFactoryService)
	return dataFactorySvc, nil
}

func (a *mqlAzureSubscription) synapse() (*mqlAzureSubscriptionSynapseService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionSynapseService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	synapseSvc := svc.(*mqlAzureSubscriptionSynapseService)
	return synapseSvc, nil
}

func (a *mqlAzureSubscription) containerRegistry() (*mqlAzureSubscriptionContainerRegistryService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionContainerRegistryService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionContainerRegistryService), nil
}

func (a *mqlAzureSubscription) recoveryServices() (*mqlAzureSubscriptionRecoveryServicesService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionRecoveryServicesService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionRecoveryServicesService), nil
}

func (a *mqlAzureSubscription) dataProtection() (*mqlAzureSubscriptionDataProtectionService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionDataProtectionService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionDataProtectionService), nil
}

func (a *mqlAzureSubscription) dataBox() (*mqlAzureSubscriptionDataBoxService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionDataBoxService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionDataBoxService), nil
}

func (a *mqlAzureSubscription) netApp() (*mqlAzureSubscriptionNetAppService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetAppService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionNetAppService), nil
}

func (a *mqlAzureSubscription) fileShares() (*mqlAzureSubscriptionFileSharesService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionFileSharesService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionFileSharesService), nil
}

func (a *mqlAzureSubscription) elasticSan() (*mqlAzureSubscriptionElasticSanService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionElasticSanService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionElasticSanService), nil
}

func (a *mqlAzureSubscription) storageCache() (*mqlAzureSubscriptionStorageCacheService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionStorageCacheService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionStorageCacheService), nil
}

func (a *mqlAzureSubscription) functions() (*mqlAzureSubscriptionFunctionsService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionFunctionsService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionFunctionsService), nil
}

func (a *mqlAzureSubscription) serviceBus() (*mqlAzureSubscriptionServiceBusService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionServiceBusService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionServiceBusService), nil
}

func (a *mqlAzureSubscription) serviceFabric() (*mqlAzureSubscriptionServiceFabricService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionServiceFabricService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionServiceFabricService), nil
}

func (a *mqlAzureSubscription) eventHub() (*mqlAzureSubscriptionEventHubService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionEventHubService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionEventHubService), nil
}

func (a *mqlAzureSubscription) dns() (*mqlAzureSubscriptionDnsService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionDnsService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionDnsService), nil
}

func (a *mqlAzureSubscription) frontDoor() (*mqlAzureSubscriptionFrontDoorService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionFrontDoorService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionFrontDoorService), nil
}

func (a *mqlAzureSubscription) containerApp() (*mqlAzureSubscriptionContainerAppService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionContainerAppService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionContainerAppService), nil
}

func (a *mqlAzureSubscription) containerInstance() (*mqlAzureSubscriptionContainerInstanceService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionContainerInstanceService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionContainerInstanceService), nil
}

func (a *mqlAzureSubscription) logic() (*mqlAzureSubscriptionLogicService, error) {
	svc, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionLogicService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionLogicService), nil
}

func (a *mqlAzureSubscription) eventGrid() (*mqlAzureSubscriptionEventGridService, error) {
	svc, err := NewResource(a.MqlRuntime, "azure.subscription.eventGridService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionEventGridService), nil
}

func (a *mqlAzureSubscription) apiManagement() (*mqlAzureSubscriptionApiManagementService, error) {
	svc, err := NewResource(a.MqlRuntime, "azure.subscription.apiManagementService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionApiManagementService), nil
}

func (a *mqlAzureSubscription) purview() (*mqlAzureSubscriptionPurviewService, error) {
	svc, err := NewResource(a.MqlRuntime, "azure.subscription.purviewService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionPurviewService), nil
}

func (a *mqlAzureSubscription) search() (*mqlAzureSubscriptionSearchService, error) {
	svc, err := NewResource(a.MqlRuntime, "azure.subscription.searchService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionSearchService), nil
}

func (a *mqlAzureSubscription) lighthouse() (*mqlAzureSubscriptionLighthouseService, error) {
	svc, err := NewResource(a.MqlRuntime, "azure.subscription.lighthouseService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionLighthouseService), nil
}

func (a *mqlAzureSubscription) signalR() (*mqlAzureSubscriptionSignalRService, error) {
	svc, err := NewResource(a.MqlRuntime, "azure.subscription.signalRService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionSignalRService), nil
}

func (a *mqlAzureSubscription) webPubSub() (*mqlAzureSubscriptionWebPubSubService, error) {
	svc, err := NewResource(a.MqlRuntime, "azure.subscription.webPubSubService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionWebPubSubService), nil
}

func (a *mqlAzureSubscription) desktopVirtualization() (*mqlAzureSubscriptionDesktopVirtualizationService, error) {
	svc, err := NewResource(a.MqlRuntime, "azure.subscription.desktopVirtualizationService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionDesktopVirtualizationService), nil
}

func (a *mqlAzureSubscription) automation() (*mqlAzureSubscriptionAutomationService, error) {
	svc, err := NewResource(a.MqlRuntime, "azure.subscription.automationService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionAutomationService), nil
}

func (a *mqlAzureSubscription) kusto() (*mqlAzureSubscriptionKustoService, error) {
	svc, err := NewResource(a.MqlRuntime, "azure.subscription.kustoService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionKustoService), nil
}

func (a *mqlAzureSubscription) appConfiguration() (*mqlAzureSubscriptionAppConfigurationService, error) {
	svc, err := NewResource(a.MqlRuntime, "azure.subscription.appConfigurationService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionAppConfigurationService), nil
}

func (a *mqlAzureSubscription) cognitiveServices() (*mqlAzureSubscriptionCognitiveServicesService, error) {
	svc, err := NewResource(a.MqlRuntime, "azure.subscription.cognitiveServicesService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionCognitiveServicesService), nil
}

func (a *mqlAzureSubscription) sentinel() (*mqlAzureSubscriptionSentinelService, error) {
	svc, err := NewResource(a.MqlRuntime, "azure.subscription.sentinelService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionSentinelService), nil
}

func (a *mqlAzureSubscription) machineLearning() (*mqlAzureSubscriptionMachineLearningService, error) {
	svc, err := NewResource(a.MqlRuntime, "azure.subscription.machineLearningService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(a.SubscriptionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return svc.(*mqlAzureSubscriptionMachineLearningService), nil
}
