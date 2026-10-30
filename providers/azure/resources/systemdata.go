// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// azureSystemData builds the typed azure.subscription.systemData resource from
// the raw systemData dict already attached to a resource. The dict is produced
// by convert.JsonToDict on the SDK's SystemData struct, so timestamps arrive as
// RFC 3339 strings. Returns nil when the resource carries no system metadata.
func azureSystemData(runtime *plugin.Runtime, parentID string, raw any) (*mqlAzureSubscriptionSystemData, error) {
	m, ok := raw.(map[string]any)
	if !ok || len(m) == 0 {
		return nil, nil
	}

	getStr := func(key string) string {
		if v, ok := m[key].(string); ok {
			return v
		}
		return ""
	}
	getTime := func(key string) *time.Time {
		s, ok := m[key].(string)
		if !ok || s == "" {
			return nil
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return nil
		}
		return &t
	}

	res, err := CreateResource(runtime, "azure.subscription.systemData", map[string]*llx.RawData{
		"__id":               llx.StringData(parentID + "/systemData"),
		"createdBy":          llx.StringData(getStr("createdBy")),
		"createdByType":      llx.StringData(getStr("createdByType")),
		"createdAt":          llx.TimeDataPtr(getTime("createdAt")),
		"lastModifiedBy":     llx.StringData(getStr("lastModifiedBy")),
		"lastModifiedByType": llx.StringData(getStr("lastModifiedByType")),
		"lastModifiedAt":     llx.TimeDataPtr(getTime("lastModifiedAt")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionSystemData), nil
}

// systemMetadataFromRaw builds the typed system-metadata resource from a raw
// systemData dict and marks the field null when the resource carries none.
func systemMetadataFromRaw(runtime *plugin.Runtime, parentID string, raw any, field *plugin.TValue[*mqlAzureSubscriptionSystemData]) (*mqlAzureSubscriptionSystemData, error) {
	sd, err := azureSystemData(runtime, parentID, raw)
	if err != nil {
		return nil, err
	}
	if sd == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return sd, nil
}

func (a *mqlAzureSubscriptionResource) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionComputeServiceVm) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionComputeServiceDisk) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionComputeServiceSnapshot) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionComputeServiceVmScaleSet) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionComputeServiceHybridMachine) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionComputeServiceHybridMachineExtension) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionStorageServiceAccount) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionKeyVaultServiceVault) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.systemDataRaw(), &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionAksServiceCluster) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionContainerRegistryServiceRegistry) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionWebServiceAppsite) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCognitiveServicesServiceAccount) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccount) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionAppConfigurationServiceConfigurationStore) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionKustoServiceCluster) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionEventHubServiceNamespace) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionEventHubServiceNamespaceEventHub) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCacheServiceRedisInstance) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionDeployment) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}
