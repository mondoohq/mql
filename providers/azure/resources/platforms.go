// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "go.mondoo.com/mql/providers-sdk/v1/plugin"

// Platforms is the static catalog of platforms the Azure provider can emit
// during discovery: the subscription root plus one entry per discoverable Azure
// object type. The subscription root is an "api" platform; each object is an
// "azure-object", all running in the "azure" runtime. This is the single source
// of truth for both the provider config (config.Config.Platforms) and the
// runtime builders in discovery.go.
var Platforms = []*plugin.PlatformInfo{
	{Name: "azure", Title: "Azure Subscription", Kind: []string{"api"}, Runtime: []string{"azure"}},
	{Name: "azure-compute-vm", Title: "Azure Compute VM", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-compute-vm-api", Title: "Azure Compute VM", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-sql-server", Title: "Azure SQL Database Server", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-postgresql-flexible-server", Title: "Azure PostgreSQL Flexible Server", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-mysql-flexible-server", Title: "Azure MySQL Flexible Server", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-aks-cluster", Title: "Azure AKS Cluster", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-app-service-webapp", Title: "Azure App Service App", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-cache-redis-instance", Title: "Azure Cache for Redis Instance", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-batch-account", Title: "Azure Batch Account", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-storage-account", Title: "Azure Storage Account", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-storage-container", Title: "Azure Storage Account Container", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-network-security-group", Title: "Azure Network Security Group", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-virtual-network", Title: "Azure Virtual Network", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-application-gateway", Title: "Azure Application Gateway", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-firewall", Title: "Azure Firewall", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-function-app", Title: "Azure Function App", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-container-app", Title: "Azure Container App", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-keyvault-vault", Title: "Azure Key Vault", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-keyvault-managedhsm", Title: "Azure Key Vault Managed HSM", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-iot-iothub", Title: "Azure IoT Hub", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-cosmosdb", Title: "Azure Cosmos DB Account", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-container-registry", Title: "Azure Container Registry", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-recovery-services-vault", Title: "Azure Recovery Services Vault", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-synapse-workspace", Title: "Azure Synapse Analytics Workspace", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-datafactory", Title: "Azure Data Factory", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
	{Name: "azure-cognitiveservices-account", Title: "Azure AI Services Account", Kind: []string{"azure-object"}, Runtime: []string{"azure"}},
}

var platformsByName = plugin.PlatformsByName(Platforms)

// PlatformByName returns the static descriptor for a platform name, or nil if
// the name is not in the catalog.
func PlatformByName(name string) *plugin.PlatformInfo {
	return platformsByName[name]
}
