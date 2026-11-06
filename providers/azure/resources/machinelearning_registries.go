// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	ml "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/machinelearning/armmachinelearning/v4"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAzureSubscriptionMachineLearningService) registries() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	client, err := ml.NewRegistriesClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListBySubscriptionPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, classifyAzureRefusal(err, "Microsoft.MachineLearningServices/registries/read")
		}
		for _, reg := range page.Value {
			if reg == nil || reg.ID == nil || *reg.ID == "" {
				continue
			}
			mqlReg, err := machineLearningRegistryToMql(a.MqlRuntime, reg)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlReg)
		}
	}
	return res, nil
}

func machineLearningRegistryToMql(runtime *plugin.Runtime, reg *ml.Registry) (*mqlAzureSubscriptionMachineLearningServiceRegistry, error) {
	props := orZero(reg.Properties)
	args := map[string]*llx.RawData{
		"id":                            llx.StringDataPtr(reg.ID),
		"name":                          llx.StringDataPtr(reg.Name),
		"location":                      llx.StringDataPtr(reg.Location),
		"tags":                          llx.MapData(convert.PtrMapStrToInterface(reg.Tags), types.String),
		"kind":                          llx.StringDataPtr(reg.Kind),
		"publicNetworkAccess":           llx.StringDataPtr(props.PublicNetworkAccess),
		"intellectualPropertyPublisher": llx.StringDataPtr(props.IntellectualPropertyPublisher),
		"discoveryUrl":                  llx.StringDataPtr(props.DiscoveryURL),
		"mlFlowRegistryUri":             llx.StringDataPtr(props.MlFlowRegistryURI),
	}
	regSku := orZero(reg.SKU)
	if err := setSkuData(runtime, args, skuName(regSku.Name), skuTier(regSku.Tier), skuSize(regSku.Size), skuFamily(regSku.Family), skuCapacity(regSku.Capacity)); err != nil {
		return nil, err
	}
	regIdentity := orZero(reg.Identity)
	if err := setResourceIdentity(runtime, args, sortedUserAssignedIdentityIDs(regIdentity.UserAssignedIdentities),
		identityType(regIdentity.Type), identityPrincipalId(regIdentity.PrincipalID), identityTenantId(regIdentity.TenantID)); err != nil {
		return nil, err
	}
	res, err := CreateResource(runtime, ResourceAzureSubscriptionMachineLearningServiceRegistry, args)
	if err != nil {
		return nil, err
	}
	mqlReg := res.(*mqlAzureSubscriptionMachineLearningServiceRegistry)
	sysData, err := convert.JsonToDict(reg.SystemData)
	if err != nil {
		return nil, err
	}
	mqlReg.cacheSystemData = sysData
	mqlReg.cachePrivateEndpointConnections = props.RegistryPrivateEndpointConnections
	mqlReg.cacheRegions = props.RegionDetails
	return mqlReg, nil
}

type mqlAzureSubscriptionMachineLearningServiceRegistryInternal struct {
	cacheSystemData                 any
	cachePrivateEndpointConnections []*ml.RegistryPrivateEndpointConnection
	cacheRegions                    []*ml.RegistryRegionArmDetails
}

func (a *mqlAzureSubscriptionMachineLearningServiceRegistry) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceRegistry) privateEndpointConnections() ([]any, error) {
	return azurePrivateEndpointConnectionsToMql(a.MqlRuntime, a.cachePrivateEndpointConnections)
}

func (a *mqlAzureSubscriptionMachineLearningServiceRegistry) roleAssignments() ([]any, error) {
	return roleAssignmentsForScope(a.MqlRuntime, a.Id.Data, "machine learning registry")
}

func (a *mqlAzureSubscriptionMachineLearningServiceRegistry) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionMachineLearningServiceRegistry) regions() ([]any, error) {
	return mlRegistryRegionsToMql(a.MqlRuntime, a.Id.Data, a.cacheRegions)
}

// mlRegistryRegionsToMql builds one region entry per replication region. A
// region has no id of its own, so its cache key is the registry id plus the
// location.
func mlRegistryRegionsToMql(runtime *plugin.Runtime, registryId string, regions []*ml.RegistryRegionArmDetails) ([]any, error) {
	res := make([]any, 0, len(regions))
	for _, r := range regions {
		if r == nil || r.Location == nil || *r.Location == "" {
			continue
		}
		acrIds, storageIds := mlRegistryRegionResourceIds(r)
		mqlRegion, err := CreateResource(runtime, ResourceAzureSubscriptionMachineLearningServiceRegistryRegion, map[string]*llx.RawData{
			"__id":     llx.StringData(subResourceCacheID(nil, registryId, "regions", *r.Location)),
			"location": llx.StringDataPtr(r.Location),
		})
		if err != nil {
			return nil, err
		}
		region := mqlRegion.(*mqlAzureSubscriptionMachineLearningServiceRegistryRegion)
		region.cacheContainerRegistryIds = acrIds
		region.cacheStorageAccountIds = storageIds
		res = append(res, region)
	}
	return res, nil
}

// mlRegistryRegionResourceIds collects the ARM ids of the container registries
// and storage accounts backing a region, whether Azure created them for the
// registry or the customer brought their own.
func mlRegistryRegionResourceIds(r *ml.RegistryRegionArmDetails) (acrIds []string, storageIds []string) {
	armId := func(id *ml.ArmResourceID) string {
		if id == nil || id.ResourceID == nil {
			return ""
		}
		return *id.ResourceID
	}
	for _, acr := range r.AcrDetails {
		if acr == nil {
			continue
		}
		if acr.SystemCreatedAcrAccount != nil {
			if id := armId(acr.SystemCreatedAcrAccount.ArmResourceID); id != "" {
				acrIds = append(acrIds, id)
			}
		}
		if acr.UserCreatedAcrAccount != nil {
			if id := armId(acr.UserCreatedAcrAccount.ArmResourceID); id != "" {
				acrIds = append(acrIds, id)
			}
		}
	}
	for _, sa := range r.StorageAccountDetails {
		if sa == nil {
			continue
		}
		if sa.SystemCreatedStorageAccount != nil {
			if id := armId(sa.SystemCreatedStorageAccount.ArmResourceID); id != "" {
				storageIds = append(storageIds, id)
			}
		}
		if sa.UserCreatedStorageAccount != nil {
			if id := armId(sa.UserCreatedStorageAccount.ArmResourceID); id != "" {
				storageIds = append(storageIds, id)
			}
		}
	}
	return acrIds, storageIds
}

type mqlAzureSubscriptionMachineLearningServiceRegistryRegionInternal struct {
	cacheContainerRegistryIds []string
	cacheStorageAccountIds    []string
}

func (a *mqlAzureSubscriptionMachineLearningServiceRegistryRegion) containerRegistries() ([]any, error) {
	res := make([]any, 0, len(a.cacheContainerRegistryIds))
	for _, id := range a.cacheContainerRegistryIds {
		r, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionContainerRegistryServiceRegistry,
			map[string]*llx.RawData{"id": llx.StringData(id)})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceRegistryRegion) storageAccounts() ([]any, error) {
	res := make([]any, 0, len(a.cacheStorageAccountIds))
	for _, id := range a.cacheStorageAccountIds {
		r, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionStorageServiceAccount,
			map[string]*llx.RawData{"id": llx.StringData(id)})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}
