// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	cosmosdb "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmosforpostgresql/armcosmosforpostgresql"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mongocluster/armmongocluster"
)

func (a *mqlAzureSubscriptionCosmosDbService) id() (string, error) {
	return "azure.subscription.cosmosdb/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionCosmosDbService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func initAzureSubscriptionCosmosDbServiceAccount(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromServiceList(runtime, args,
		ResourceAzureSubscriptionCosmosDbService,
		func(s *mqlAzureSubscriptionCosmosDbService) *plugin.TValue[[]any] { return s.GetAccounts() },
		ResourceAzureSubscriptionCosmosDbServiceAccount)
}

func (a *mqlAzureSubscriptionCosmosDbService) accounts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId := a.SubscriptionId.Data

	return fetchCosmosDBAccounts(ctx, a.MqlRuntime, conn, subId)
}

func (a *mqlAzureSubscriptionCosmosDbService) mongoClusters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId := a.SubscriptionId.Data

	return fetchMongoClusters(ctx, a.MqlRuntime, conn, subId)
}

func (a *mqlAzureSubscriptionCosmosDbService) postgresqlClusters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	subId := a.SubscriptionId.Data

	return fetchCosmosForPostgres(ctx, a.MqlRuntime, conn, subId)
}

type mqlAzureSubscriptionCosmosDbServiceAccountInternal struct {
	cacheKeyVaultKeyUri          string
	cacheBackupType              string
	cacheBackupIntervalMinutes   int64
	cacheBackupRetentionHours    int64
	cacheBackupRedundancy        string
	cacheSystemData              any
	cacheUserAssignedIdentityIds []string
}

func fetchCosmosDBAccounts(ctx context.Context, runtime *plugin.Runtime, conn *connection.AzureConnection, subId string) ([]any, error) {
	accClient, err := cosmosdb.NewDatabaseAccountsClient(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := accClient.NewListPager(&cosmosdb.DatabaseAccountsClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, account := range page.Value {
			if account == nil || account.ID == nil {
				continue
			}
			mqlCosmosDbAccount, err := cosmosAccountToMql(runtime, account)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlCosmosDbAccount)
		}
	}
	return res, nil
}

func cosmosAccountToMql(runtime *plugin.Runtime, account *cosmosdb.DatabaseAccountGetResults) (plugin.Resource, error) {
	properties, err := convert.JsonToDict(account.Properties)
	if err != nil {
		return nil, err
	}

	var publicNetworkAccess *string
	var disableLocalAuth *bool
	var isVirtualNetworkFilterEnabled *bool
	var disableKeyBasedMetadataWriteAccess *bool
	var enableAutomaticFailover *bool
	var enableMultipleWriteLocations *bool
	var minimalTlsVersion *string
	var defaultIdentity *string
	if account.Properties != nil {
		publicNetworkAccess = (*string)(account.Properties.PublicNetworkAccess)
		disableLocalAuth = account.Properties.DisableLocalAuth
		isVirtualNetworkFilterEnabled = account.Properties.IsVirtualNetworkFilterEnabled
		disableKeyBasedMetadataWriteAccess = account.Properties.DisableKeyBasedMetadataWriteAccess
		enableAutomaticFailover = account.Properties.EnableAutomaticFailover
		enableMultipleWriteLocations = account.Properties.EnableMultipleWriteLocations
		minimalTlsVersion = (*string)(account.Properties.MinimalTLSVersion)
		defaultIdentity = account.Properties.DefaultIdentity
	}

	ipRangeFilter := []any{}
	if account.Properties != nil && account.Properties.IPRules != nil {
		for _, rule := range account.Properties.IPRules {
			if rule != nil && rule.IPAddressOrRange != nil {
				ipRangeFilter = append(ipRangeFilter, *rule.IPAddressOrRange)
			}
		}
	}

	var backupType string
	var backupIntervalMinutes, backupRetentionHours int64
	var backupRedundancy string
	if account.Properties != nil && account.Properties.BackupPolicy != nil {
		bp := account.Properties.BackupPolicy
		if bp.GetBackupPolicy().Type != nil {
			backupType = string(*bp.GetBackupPolicy().Type)
		}
		if periodic, ok := bp.(*cosmosdb.PeriodicModeBackupPolicy); ok && periodic.PeriodicModeProperties != nil {
			if periodic.PeriodicModeProperties.BackupIntervalInMinutes != nil {
				backupIntervalMinutes = int64(*periodic.PeriodicModeProperties.BackupIntervalInMinutes)
			}
			if periodic.PeriodicModeProperties.BackupRetentionIntervalInHours != nil {
				backupRetentionHours = int64(*periodic.PeriodicModeProperties.BackupRetentionIntervalInHours)
			}
			if periodic.PeriodicModeProperties.BackupStorageRedundancy != nil {
				backupRedundancy = string(*periodic.PeriodicModeProperties.BackupStorageRedundancy)
			}
		}
	}

	var identityType, identityPrincipalId, identityTenantId *string
	var userAssignedIdentityIds []string
	if account.Identity != nil {
		identityType = cosmosEnumStrPtr(account.Identity.Type)
		identityPrincipalId = account.Identity.PrincipalID
		identityTenantId = account.Identity.TenantID
		userAssignedIdentityIds = sortedUserAssignedIdentityIDs(account.Identity.UserAssignedIdentities)
	}

	defaultConsistencyLevel, networkAclBypass, corsAllowedOrigins, locations := cosmosNetworkConsistency(account.Properties)

	var customerManagedKeyStatus, encryptionKeyVersion, documentEndpoint *string
	var analyticalStorageSchemaType *string
	var enableAnalyticalStorage, enableFreeTier, enableBurstCapacity, enablePartitionMerge *bool
	capabilities := []any{}
	networkAclBypassResourceIds := []any{}
	var keysMetadata any
	if p := account.Properties; p != nil {
		customerManagedKeyStatus = p.CustomerManagedKeyStatus
		encryptionKeyVersion = p.KeyVaultKeyURIVersion
		documentEndpoint = p.DocumentEndpoint
		enableAnalyticalStorage = p.EnableAnalyticalStorage
		enableFreeTier = p.EnableFreeTier
		enableBurstCapacity = p.EnableBurstCapacity
		enablePartitionMerge = p.EnablePartitionMerge
		if asc := p.AnalyticalStorageConfiguration; asc != nil {
			analyticalStorageSchemaType = stringEnumPtr(asc.SchemaType)
		}
		for _, c := range p.Capabilities {
			if c != nil && c.Name != nil {
				capabilities = append(capabilities, *c.Name)
			}
		}
		networkAclBypassResourceIds = strPtrsToAny(p.NetworkACLBypassResourceIDs)
		keysMetadata, err = convert.JsonToDict(p.KeysMetadata)
		if err != nil {
			return nil, err
		}
	}

	masterKeyMetadata, err := cosmosKeysMetadataToMql(runtime, convert.ToValue(account.ID), orZero(account.Properties).KeysMetadata)
	if err != nil {
		return nil, err
	}

	virtualNetworkRules := []any{}
	if account.Properties != nil && account.Properties.VirtualNetworkRules != nil {
		for _, rule := range account.Properties.VirtualNetworkRules {
			if rule == nil {
				continue
			}
			var subnetId string
			var ignoreMissing bool
			if rule.ID != nil {
				subnetId = *rule.ID
			}
			if rule.IgnoreMissingVNetServiceEndpoint != nil {
				ignoreMissing = *rule.IgnoreMissingVNetServiceEndpoint
			}
			// convert.ToValue rather than a bare deref: the list path guards
			// account.ID, but the init path reaches this function straight from
			// a Get response.
			ruleId := convert.ToValue(account.ID) + "/virtualNetworkRules/" + subnetId
			mqlRule, err := CreateResource(runtime, "azure.subscription.cosmosDbService.account.virtualNetworkRule",
				map[string]*llx.RawData{
					"__id":                             llx.StringData(ruleId),
					"id":                               llx.StringData(ruleId),
					"subnetId":                         llx.StringData(subnetId),
					"ignoreMissingVNetServiceEndpoint": llx.BoolData(ignoreMissing),
				})
			if err != nil {
				return nil, err
			}
			virtualNetworkRules = append(virtualNetworkRules, mqlRule)
		}
	}

	mqlCosmosDbAccount, err := CreateResource(runtime, "azure.subscription.cosmosDbService.account",
		map[string]*llx.RawData{
			"__id":                               llx.StringDataPtr(account.ID),
			"id":                                 llx.StringDataPtr(account.ID),
			"name":                               llx.StringDataPtr(account.Name),
			"tags":                               llx.MapData(convert.PtrMapStrToInterface(account.Tags), types.String),
			"location":                           llx.StringDataPtr(account.Location),
			"kind":                               llx.StringDataPtr((*string)(account.Kind)),
			"type":                               llx.StringDataPtr(account.Type),
			"properties":                         llx.DictData(properties),
			"publicNetworkAccess":                llx.StringDataPtr(publicNetworkAccess),
			"disableLocalAuth":                   llx.BoolDataPtr(disableLocalAuth),
			"isVirtualNetworkFilterEnabled":      llx.BoolDataPtr(isVirtualNetworkFilterEnabled),
			"disableKeyBasedMetadataWriteAccess": llx.BoolDataPtr(disableKeyBasedMetadataWriteAccess),
			"enableAutomaticFailover":            llx.BoolDataPtr(enableAutomaticFailover),
			"enableMultipleWriteLocations":       llx.BoolDataPtr(enableMultipleWriteLocations),
			"ipRangeFilter":                      llx.ArrayData(ipRangeFilter, types.String),
			"minimalTlsVersion":                  llx.StringDataPtr(minimalTlsVersion),
			"defaultIdentity":                    llx.StringDataPtr(defaultIdentity),
			"backupType":                         llx.StringData(backupType),
			"backupIntervalInMinutes":            llx.IntData(backupIntervalMinutes),
			"backupRetentionIntervalInHours":     llx.IntData(backupRetentionHours),
			"backupStorageRedundancy":            llx.StringData(backupRedundancy),
			"defaultConsistencyLevel":            llx.StringDataPtr(defaultConsistencyLevel),
			"networkAclBypass":                   llx.StringDataPtr(networkAclBypass),
			"customerManagedKeyStatus":           llx.StringDataPtr(customerManagedKeyStatus),
			"encryptionKeyVersion":               llx.StringDataPtr(encryptionKeyVersion),
			"keysMetadata":                       llx.DictData(keysMetadata),
			"masterKeyMetadata":                  masterKeyMetadata,
			"capabilities":                       llx.ArrayData(capabilities, types.String),
			"enableAnalyticalStorage":            llx.BoolDataPtr(enableAnalyticalStorage),
			"analyticalStorageSchemaType":        llx.StringDataPtr(analyticalStorageSchemaType),
			"enableFreeTier":                     llx.BoolDataPtr(enableFreeTier),
			"enableBurstCapacity":                llx.BoolDataPtr(enableBurstCapacity),
			"enablePartitionMerge":               llx.BoolDataPtr(enablePartitionMerge),
			"networkAclBypassResourceIds":        llx.ArrayData(networkAclBypassResourceIds, types.String),
			"documentEndpoint":                   llx.StringDataPtr(documentEndpoint),
			"corsAllowedOrigins":                 llx.ArrayData(corsAllowedOrigins, types.String),
			"locations":                          llx.ArrayData(locations, types.String),
			"virtualNetworkRules":                llx.ArrayData(virtualNetworkRules, types.Resource("azure.subscription.cosmosDbService.account.virtualNetworkRule")),
			"identityType":                       llx.StringDataPtr(identityType),
			"principalId":                        llx.StringDataPtr(identityPrincipalId),
			"tenantId":                           llx.StringDataPtr(identityTenantId),
		})
	if err != nil {
		return nil, err
	}
	mqlAccount := mqlCosmosDbAccount.(*mqlAzureSubscriptionCosmosDbServiceAccount)
	mqlAccount.cacheUserAssignedIdentityIds = userAssignedIdentityIds
	if account.Properties != nil && account.Properties.KeyVaultKeyURI != nil {
		mqlAccount.cacheKeyVaultKeyUri = *account.Properties.KeyVaultKeyURI
	}
	sysData, err := convert.JsonToDict(account.SystemData)
	if err != nil {
		return nil, err
	}
	mqlAccount.cacheSystemData = sysData
	return mqlCosmosDbAccount, nil
}

// cosmosEnumStrPtr converts a pointer to a string-based SDK enum into a *string,
// preserving nil so absent values stay null rather than becoming an empty string.
func cosmosEnumStrPtr[T ~string](v *T) *string {
	if v == nil {
		return nil
	}
	s := string(*v)
	return &s
}

// cosmosCorsOrigins flattens a Cosmos DB account's CORS policies into one origin
// per element.
//
// ARM models allowedOrigins as a single string holding a comma-separated list
// rather than an array, so reporting it whole produced one element such as
// "https://app.example.com,*". An origin inside that element matches nothing a
// query would compare against: corsAllowedOrigins.none(_ == "*") passed on an
// account that allows every origin, and any(_ == "https://app.example.com")
// failed on an account that allows it.
//
// Duplicates are kept. An account can carry several CORS policies, and repeating
// an origin across them is what the account is actually configured with.
func cosmosCorsOrigins(policies []*cosmosdb.CorsPolicy) []any {
	origins := []any{}
	for _, cors := range policies {
		if cors == nil || cors.AllowedOrigins == nil {
			continue
		}
		for _, origin := range strings.Split(*cors.AllowedOrigins, ",") {
			if origin = strings.TrimSpace(origin); origin != "" {
				origins = append(origins, origin)
			}
		}
	}
	return origins
}

// cosmosNetworkConsistency extracts the default consistency level, network ACL
// bypass setting, CORS allowed origins, and deployed region names from a Cosmos
// DB account's properties. Consistency level and ACL bypass stay nil (null in
// MQL) when absent; the slices are always non-nil so callers can assert on
// length without a null guard.
func cosmosNetworkConsistency(props *cosmosdb.DatabaseAccountGetProperties) (defaultConsistencyLevel, networkAclBypass *string, corsAllowedOrigins, locations []any) {
	corsAllowedOrigins = []any{}
	locations = []any{}
	if props == nil {
		return nil, nil, corsAllowedOrigins, locations
	}
	if props.ConsistencyPolicy != nil {
		defaultConsistencyLevel = cosmosEnumStrPtr(props.ConsistencyPolicy.DefaultConsistencyLevel)
	}
	networkAclBypass = cosmosEnumStrPtr(props.NetworkACLBypass)
	corsAllowedOrigins = cosmosCorsOrigins(props.Cors)
	for _, loc := range props.Locations {
		if loc != nil && loc.LocationName != nil {
			locations = append(locations, *loc.LocationName)
		}
	}
	return defaultConsistencyLevel, networkAclBypass, corsAllowedOrigins, locations
}

// fetchMongoClusters lists the Cosmos DB for MongoDB (vCore) clusters
// (Microsoft.DocumentDB/mongoClusters) in the subscription. These are
// distinct Azure resources from classic Cosmos DB database accounts.
func fetchMongoClusters(ctx context.Context, runtime *plugin.Runtime, conn *connection.AzureConnection, subId string) ([]any, error) {
	client, err := armmongocluster.NewMongoClustersClient(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListPager(&armmongocluster.MongoClustersClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, cluster := range page.Value {
			if cluster == nil {
				continue
			}
			mqlCluster, err := newMongoClusterResource(runtime, cluster)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlCluster)
		}
	}
	return res, nil
}

func newMongoClusterResource(runtime *plugin.Runtime, cluster *armmongocluster.MongoCluster) (*mqlAzureSubscriptionCosmosDbServiceMongoCluster, error) {
	args := map[string]*llx.RawData{
		"__id":                  llx.StringDataPtr(cluster.ID),
		"id":                    llx.StringDataPtr(cluster.ID),
		"name":                  llx.StringDataPtr(cluster.Name),
		"location":              llx.StringDataPtr(cluster.Location),
		"tags":                  llx.MapData(convert.PtrMapStrToInterface(cluster.Tags), types.String),
		"provisioningState":     llx.NilData,
		"clusterStatus":         llx.NilData,
		"serverVersion":         llx.NilData,
		"infrastructureVersion": llx.NilData,
		"publicNetworkAccess":   llx.NilData,
		"networkBypassMode":     llx.NilData,
		"computeTier":           llx.NilData,
		"storageSizeGb":         llx.NilData,
		"storageType":           llx.NilData,
		"shardCount":            llx.NilData,
		"highAvailabilityMode":  llx.NilData,
		"administratorLogin":    llx.NilData,
		"authModes":             llx.NilData,
		"dataApiMode":           llx.NilData,
		"earliestRestoreTime":   llx.NilData,
		"replicationRole":       llx.NilData,
		"replicationState":      llx.NilData,
		"replicationSourceId":   llx.NilData,
	}

	var keyVaultKeyUri string
	if p := cluster.Properties; p != nil {
		args["provisioningState"] = llx.StringDataPtr(cosmosEnumStrPtr(p.ProvisioningState))
		args["clusterStatus"] = llx.StringDataPtr(cosmosEnumStrPtr(p.ClusterStatus))
		args["serverVersion"] = llx.StringDataPtr(p.ServerVersion)
		args["infrastructureVersion"] = llx.StringDataPtr(p.InfrastructureVersion)
		args["publicNetworkAccess"] = llx.StringDataPtr(cosmosEnumStrPtr(p.PublicNetworkAccess))
		args["networkBypassMode"] = llx.StringDataPtr(cosmosEnumStrPtr(p.NetworkBypassMode))
		if p.Compute != nil {
			args["computeTier"] = llx.StringDataPtr(p.Compute.Tier)
		}
		if p.Storage != nil {
			args["storageSizeGb"] = llx.IntDataPtr(p.Storage.SizeGb)
			args["storageType"] = llx.StringDataPtr(cosmosEnumStrPtr(p.Storage.Type))
		}
		if p.Sharding != nil {
			args["shardCount"] = llx.IntDataPtr(p.Sharding.ShardCount)
		}
		if p.HighAvailability != nil {
			args["highAvailabilityMode"] = llx.StringDataPtr(cosmosEnumStrPtr(p.HighAvailability.TargetMode))
		}
		if p.Administrator != nil {
			args["administratorLogin"] = llx.StringDataPtr(p.Administrator.UserName)
		}
		if p.AuthConfig != nil {
			modes := []any{}
			for _, m := range p.AuthConfig.AllowedModes {
				if m != nil {
					modes = append(modes, string(*m))
				}
			}
			args["authModes"] = llx.ArrayData(modes, types.String)
		}
		if p.DataAPI != nil {
			args["dataApiMode"] = llx.StringDataPtr(cosmosEnumStrPtr(p.DataAPI.Mode))
		}
		if p.Backup != nil {
			args["earliestRestoreTime"] = parseAzureDateString(p.Backup.EarliestRestoreTime)
		}
		if p.Replica != nil {
			args["replicationRole"] = llx.StringDataPtr(cosmosEnumStrPtr(p.Replica.Role))
			args["replicationState"] = llx.StringDataPtr(cosmosEnumStrPtr(p.Replica.ReplicationState))
			args["replicationSourceId"] = llx.StringDataPtr(p.Replica.SourceResourceID)
		}
		if p.Encryption != nil && p.Encryption.CustomerManagedKeyEncryption != nil &&
			p.Encryption.CustomerManagedKeyEncryption.KeyEncryptionKeyURL != nil {
			keyVaultKeyUri = *p.Encryption.CustomerManagedKeyEncryption.KeyEncryptionKeyURL
		}
	}

	resource, err := CreateResource(runtime, "azure.subscription.cosmosDbService.mongoCluster", args)
	if err != nil {
		return nil, err
	}
	mqlCluster := resource.(*mqlAzureSubscriptionCosmosDbServiceMongoCluster)
	mqlCluster.cacheKeyVaultKeyUri = keyVaultKeyUri
	sysData, err := convert.JsonToDict(cluster.SystemData)
	if err != nil {
		return nil, err
	}
	mqlCluster.cacheSystemData = sysData
	return mqlCluster, nil
}

// fetchCosmosForPostgres lists the Cosmos DB for PostgreSQL clusters
// (Microsoft.DBforPostgreSQL/serverGroupsv2) in the subscription. These
// are distinct Azure resources from classic Cosmos DB database accounts.
func fetchCosmosForPostgres(ctx context.Context, runtime *plugin.Runtime, conn *connection.AzureConnection, subId string) ([]any, error) {
	resClient, err := armcosmosforpostgresql.NewClustersClient(subId, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := resClient.NewListPager(&armcosmosforpostgresql.ClustersClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, cluster := range page.Value {
			if cluster == nil {
				continue
			}
			mqlCluster, err := newPostgresClusterResource(runtime, cluster)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlCluster)
		}
	}
	return res, nil
}

func newPostgresClusterResource(runtime *plugin.Runtime, cluster *armcosmosforpostgresql.Cluster) (*mqlAzureSubscriptionCosmosDbServicePostgresqlCluster, error) {
	args := map[string]*llx.RawData{
		"__id":                            llx.StringDataPtr(cluster.ID),
		"id":                              llx.StringDataPtr(cluster.ID),
		"name":                            llx.StringDataPtr(cluster.Name),
		"location":                        llx.StringDataPtr(cluster.Location),
		"tags":                            llx.MapData(convert.PtrMapStrToInterface(cluster.Tags), types.String),
		"provisioningState":               llx.NilData,
		"state":                           llx.NilData,
		"postgresqlVersion":               llx.NilData,
		"citusVersion":                    llx.NilData,
		"administratorLogin":              llx.NilData,
		"enableHa":                        llx.NilData,
		"enableShardsOnCoordinator":       llx.NilData,
		"coordinatorEnablePublicIpAccess": llx.NilData,
		"coordinatorServerEdition":        llx.NilData,
		"coordinatorStorageQuotaInMb":     llx.NilData,
		"coordinatorVCores":               llx.NilData,
		"nodeCount":                       llx.NilData,
		"nodeEnablePublicIpAccess":        llx.NilData,
		"nodeServerEdition":               llx.NilData,
		"nodeStorageQuotaInMb":            llx.NilData,
		"nodeVCores":                      llx.NilData,
		"preferredPrimaryZone":            llx.NilData,
		"earliestRestoreTime":             llx.NilData,
		"sourceLocation":                  llx.NilData,
		"sourceResourceId":                llx.NilData,
		"readReplicas":                    llx.NilData,
		"maintenanceWindow":               llx.NilData,
		"maintenanceSchedule":             llx.NilData,
		"serverNames":                     llx.NilData,
	}

	if p := cluster.Properties; p != nil {
		args["provisioningState"] = llx.StringDataPtr(p.ProvisioningState)
		args["state"] = llx.StringDataPtr(p.State)
		args["postgresqlVersion"] = llx.StringDataPtr(p.PostgresqlVersion)
		args["citusVersion"] = llx.StringDataPtr(p.CitusVersion)
		args["administratorLogin"] = llx.StringDataPtr(p.AdministratorLogin)
		args["enableHa"] = llx.BoolDataPtr(p.EnableHa)
		args["enableShardsOnCoordinator"] = llx.BoolDataPtr(p.EnableShardsOnCoordinator)
		args["coordinatorEnablePublicIpAccess"] = llx.BoolDataPtr(p.CoordinatorEnablePublicIPAccess)
		args["coordinatorServerEdition"] = llx.StringDataPtr(p.CoordinatorServerEdition)
		args["coordinatorStorageQuotaInMb"] = llx.IntDataPtr(p.CoordinatorStorageQuotaInMb)
		args["coordinatorVCores"] = llx.IntDataPtr(p.CoordinatorVCores)
		args["nodeCount"] = llx.IntDataPtr(p.NodeCount)
		args["nodeEnablePublicIpAccess"] = llx.BoolDataPtr(p.NodeEnablePublicIPAccess)
		args["nodeServerEdition"] = llx.StringDataPtr(p.NodeServerEdition)
		args["nodeStorageQuotaInMb"] = llx.IntDataPtr(p.NodeStorageQuotaInMb)
		args["nodeVCores"] = llx.IntDataPtr(p.NodeVCores)
		args["preferredPrimaryZone"] = llx.StringDataPtr(p.PreferredPrimaryZone)
		args["earliestRestoreTime"] = llx.TimeDataPtr(p.EarliestRestoreTime)
		args["sourceLocation"] = llx.StringDataPtr(p.SourceLocation)
		args["sourceResourceId"] = llx.StringDataPtr(p.SourceResourceID)

		if p.ReadReplicas != nil {
			replicas := []any{}
			for _, r := range p.ReadReplicas {
				if r != nil {
					replicas = append(replicas, *r)
				}
			}
			args["readReplicas"] = llx.ArrayData(replicas, types.String)
		}
		if p.MaintenanceWindow != nil {
			mw, err := convert.JsonToDict(p.MaintenanceWindow)
			if err != nil {
				return nil, err
			}
			args["maintenanceWindow"] = llx.DictData(mw)
			schedule, err := maintenanceWindowRefData(runtime, convert.ToValue(cluster.ID),
				p.MaintenanceWindow.CustomWindow, p.MaintenanceWindow.DayOfWeek,
				p.MaintenanceWindow.StartHour, p.MaintenanceWindow.StartMinute)
			if err != nil {
				return nil, err
			}
			args["maintenanceSchedule"] = schedule
		}
		if p.ServerNames != nil {
			names := []any{}
			for _, s := range p.ServerNames {
				if s == nil {
					continue
				}
				d, err := convert.JsonToDict(s)
				if err != nil {
					return nil, err
				}
				names = append(names, d)
			}
			args["serverNames"] = llx.ArrayData(names, types.Dict)
		}
	}

	resource, err := CreateResource(runtime, "azure.subscription.cosmosDbService.postgresqlCluster", args)
	if err != nil {
		return nil, err
	}
	mqlCluster := resource.(*mqlAzureSubscriptionCosmosDbServicePostgresqlCluster)
	sysData, err := convert.JsonToDict(cluster.SystemData)
	if err != nil {
		return nil, err
	}
	mqlCluster.cacheSystemData = sysData
	return mqlCluster, nil
}

type mqlAzureSubscriptionCosmosDbServicePostgresqlClusterInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCosmosDbServiceMongoCluster) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCosmosDbServicePostgresqlCluster) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccount) encryptionKey() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	if a.cacheKeyVaultKeyUri == "" {
		a.EncryptionKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, a.cacheKeyVaultKeyUri)
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccount) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

type mqlAzureSubscriptionCosmosDbServiceMongoClusterInternal struct {
	cacheKeyVaultKeyUri string
	cacheSystemData     any
}

func (a *mqlAzureSubscriptionCosmosDbServiceMongoCluster) encryptionKey() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	if a.cacheKeyVaultKeyUri == "" {
		a.EncryptionKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, a.cacheKeyVaultKeyUri)
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccount) privateEndpointConnections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	rid, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	accountName, err := rid.Component("databaseAccounts")
	if err != nil {
		return nil, err
	}
	client, err := cosmosdb.NewPrivateEndpointConnectionsClient(rid.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListByDatabaseAccountPager(rid.ResourceGroup, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, pec := range page.Value {
			if pec == nil {
				continue
			}
			var pecPrivateEndpointID string
			args := map[string]*llx.RawData{
				"__id": llx.StringDataPtr(pec.ID),
				"id":   llx.StringDataPtr(pec.ID),
				"name": llx.StringDataPtr(pec.Name),
				"type": llx.StringDataPtr(pec.Type),
			}
			if pec.Properties != nil {
				propsMap, err := convert.JsonToDict(pec.Properties)
				if err != nil {
					return nil, err
				}
				args["properties"] = llx.DictData(propsMap)
				if pec.Properties.PrivateEndpoint != nil {
					pecPrivateEndpointID = convert.ToValue(pec.Properties.PrivateEndpoint.ID)
				}
				if pec.Properties.ProvisioningState != nil {
					args["provisioningState"] = llx.StringDataPtr(pec.Properties.ProvisioningState)
				}
				if pec.Properties.PrivateLinkServiceConnectionState != nil {
					stateRes, err := newPrivateLinkServiceConnectionState(a.MqlRuntime, convert.ToValue(pec.ID),
						stringEnumPtr(pec.Properties.PrivateLinkServiceConnectionState.ActionsRequired),
						pec.Properties.PrivateLinkServiceConnectionState.Description,
						stringEnumPtr(pec.Properties.PrivateLinkServiceConnectionState.Status))
					if err != nil {
						return nil, err
					}
					args["privateLinkServiceConnectionState"] = llx.ResourceData(stateRes, ResourceAzureSubscriptionPrivateEndpointConnectionConnectionState)
				}
			}
			mqlConn, err := newAzurePrivateEndpointConnection(a.MqlRuntime, args, pecPrivateEndpointID)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlConn)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccount) sqlRoleDefinitions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	rid, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	accountName, err := rid.Component("databaseAccounts")
	if err != nil {
		return nil, err
	}
	client, err := cosmosdb.NewSQLResourcesClient(rid.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListSQLRoleDefinitionsPager(rid.ResourceGroup, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, def := range page.Value {
			if def == nil {
				continue
			}
			args := map[string]*llx.RawData{
				"__id":             llx.StringDataPtr(def.ID),
				"id":               llx.StringDataPtr(def.ID),
				"name":             llx.StringDataPtr(def.Name),
				"type":             llx.StringDataPtr(def.Type),
				"roleName":         llx.StringData(""),
				"roleType":         llx.StringData(""),
				"assignableScopes": llx.ArrayData([]any{}, types.String),
				"permissions":      llx.ArrayData([]any{}, types.Dict),
			}
			if def.Properties != nil {
				if def.Properties.RoleName != nil {
					args["roleName"] = llx.StringDataPtr(def.Properties.RoleName)
				}
				if def.Properties.Type != nil {
					args["roleType"] = llx.StringData(string(*def.Properties.Type))
				}
				scopes := []any{}
				for _, s := range def.Properties.AssignableScopes {
					if s != nil {
						scopes = append(scopes, *s)
					}
				}
				args["assignableScopes"] = llx.ArrayData(scopes, types.String)

				perms := []any{}
				for _, p := range def.Properties.Permissions {
					if p == nil {
						continue
					}
					m, err := convert.JsonToDict(p)
					if err != nil {
						return nil, err
					}
					perms = append(perms, m)
				}
				args["permissions"] = llx.ArrayData(perms, types.Dict)
			}
			dataPermissions, err := cosmosRolePermissionsToMql(a.MqlRuntime, convert.ToValue(def.ID), orZero(def.Properties).Permissions)
			if err != nil {
				return nil, err
			}
			args["dataPermissions"] = llx.ArrayData(dataPermissions, types.Resource("azure.subscription.cosmosDbService.account.roleDefinitionPermission"))
			mqlDef, err := CreateResource(a.MqlRuntime, "azure.subscription.cosmosDbService.account.sqlRoleDefinition", args)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(def.SystemData)
			if err != nil {
				return nil, err
			}
			mqlDef.(*mqlAzureSubscriptionCosmosDbServiceAccountSqlRoleDefinition).cacheSystemData = sysData
			res = append(res, mqlDef)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccount) sqlRoleAssignments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	rid, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	accountName, err := rid.Component("databaseAccounts")
	if err != nil {
		return nil, err
	}
	client, err := cosmosdb.NewSQLResourcesClient(rid.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListSQLRoleAssignmentsPager(rid.ResourceGroup, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, ra := range page.Value {
			if ra == nil {
				continue
			}
			args := map[string]*llx.RawData{
				"__id":             llx.StringDataPtr(ra.ID),
				"id":               llx.StringDataPtr(ra.ID),
				"name":             llx.StringDataPtr(ra.Name),
				"type":             llx.StringDataPtr(ra.Type),
				"principalId":      llx.StringData(""),
				"roleDefinitionId": llx.StringData(""),
				"scope":            llx.StringData(""),
			}
			if ra.Properties != nil {
				if ra.Properties.PrincipalID != nil {
					args["principalId"] = llx.StringDataPtr(ra.Properties.PrincipalID)
				}
				if ra.Properties.RoleDefinitionID != nil {
					args["roleDefinitionId"] = llx.StringDataPtr(ra.Properties.RoleDefinitionID)
				}
				if ra.Properties.Scope != nil {
					args["scope"] = llx.StringDataPtr(ra.Properties.Scope)
				}
			}
			mqlRA, err := CreateResource(a.MqlRuntime, "azure.subscription.cosmosDbService.account.sqlRoleAssignment", args)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(ra.SystemData)
			if err != nil {
				return nil, err
			}
			mqlRA.(*mqlAzureSubscriptionCosmosDbServiceAccountSqlRoleAssignment).cacheSystemData = sysData
			res = append(res, mqlRA)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionCosmosDbServiceAccountSqlRoleDefinitionInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountSqlRoleDefinition) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionCosmosDbServiceAccountSqlRoleAssignmentInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccountSqlRoleAssignment) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccount) diagnosticSettings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	return getDiagnosticSettings(a.Id.Data, a.MqlRuntime, conn)
}

func (a *mqlAzureSubscriptionCosmosDbServiceAccount) diagnosticSettingsCategories() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	return getDiagnosticSettingsCategories(a.Id.Data, a.MqlRuntime, conn)
}

// cosmosKeysMetadataToMql maps the account's key metadata onto its own
// resource, with one entry per master key.
//
// The generation time is the only member ARM records per key, and it is what a
// key-rotation audit reads: a primary key that has not been regenerated in
// months is the finding, and the read-only keys rotate independently of the
// read-write ones. An account whose metadata ARM does not report reads null
// rather than four keys with a zero timestamp.
func cosmosKeysMetadataToMql(runtime *plugin.Runtime, accountID string, km *cosmosdb.DatabaseAccountKeysMetadata) (*llx.RawData, error) {
	if km == nil {
		return llx.NilData, nil
	}
	if accountID == "" {
		return nil, errors.New("cannot key the Cosmos DB key metadata: the account has no id")
	}
	const resourceName = "azure.subscription.cosmosDbService.account.masterKeyMetadata"
	const entryName = "azure.subscription.cosmosDbService.account.accountKeyMetadata"

	entry := func(key string, meta *cosmosdb.AccountKeyMetadata) (*llx.RawData, error) {
		if meta == nil {
			return llx.NilData, nil
		}
		res, err := CreateResource(runtime, entryName, map[string]*llx.RawData{
			"__id":           llx.StringData(accountID + "/keysMetadata/" + key),
			"generationTime": llx.TimeDataPtr(meta.GenerationTime),
		})
		if err != nil {
			return nil, err
		}
		return llx.ResourceData(res, entryName), nil
	}

	args := map[string]*llx.RawData{"__id": llx.StringData(accountID + "/keysMetadata")}
	for key, meta := range map[string]*cosmosdb.AccountKeyMetadata{
		"primaryMasterKey":           km.PrimaryMasterKey,
		"secondaryMasterKey":         km.SecondaryMasterKey,
		"primaryReadonlyMasterKey":   km.PrimaryReadonlyMasterKey,
		"secondaryReadonlyMasterKey": km.SecondaryReadonlyMasterKey,
	} {
		data, err := entry(key, meta)
		if err != nil {
			return nil, err
		}
		args[key] = data
	}

	res, err := CreateResource(runtime, resourceName, args)
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, resourceName), nil
}
