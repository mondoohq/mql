// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	postgresql "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresql"
	flexible "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers/v5"
)

func (a *mqlAzureSubscriptionPostgreSqlService) id() (string, error) {
	return "azure.subscription.postgresql/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionPostgreSqlService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionPostgreSqlServiceDatabase) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionPostgreSqlServiceServer) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionPostgreSqlService) servers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	dbClient, err := postgresql.NewServersClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := dbClient.NewListPager(&postgresql.ServersClientListOptions{})
	res := []any{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, dbServer := range page.Value {
			if dbServer == nil {
				continue
			}
			properties := make(map[string](any))

			data, err := json.Marshal(dbServer.Properties)
			if err != nil {
				return nil, err
			}

			err = json.Unmarshal([]byte(data), &properties)
			if err != nil {
				return nil, err
			}

			var sslEnforcement *bool
			var minimalTlsVersion *string
			var publicNetworkAccess *string
			var infrastructureEncryption *bool
			var version *string
			if dbServer.Properties != nil {
				if dbServer.Properties.SSLEnforcement != nil {
					v := *dbServer.Properties.SSLEnforcement == postgresql.SSLEnforcementEnumEnabled
					sslEnforcement = &v
				}
				minimalTlsVersion = (*string)(dbServer.Properties.MinimalTLSVersion)
				publicNetworkAccess = (*string)(dbServer.Properties.PublicNetworkAccess)
				if dbServer.Properties.InfrastructureEncryption != nil {
					v := *dbServer.Properties.InfrastructureEncryption == postgresql.InfrastructureEncryptionEnabled
					infrastructureEncryption = &v
				}
				version = (*string)(dbServer.Properties.Version)
			}

			var backupRetentionDays int64
			var geoRedundantBackup string
			if dbServer.Properties != nil && dbServer.Properties.StorageProfile != nil {
				if dbServer.Properties.StorageProfile.BackupRetentionDays != nil {
					backupRetentionDays = int64(*dbServer.Properties.StorageProfile.BackupRetentionDays)
				}
				if dbServer.Properties.StorageProfile.GeoRedundantBackup != nil {
					geoRedundantBackup = string(*dbServer.Properties.StorageProfile.GeoRedundantBackup)
				}
			}

			mqlAzurePostgresServer, err := CreateResource(a.MqlRuntime, "azure.subscription.postgreSqlService.server",
				map[string]*llx.RawData{
					"id":                       llx.StringDataPtr(dbServer.ID),
					"name":                     llx.StringDataPtr(dbServer.Name),
					"location":                 llx.StringDataPtr(dbServer.Location),
					"tags":                     llx.MapData(convert.PtrMapStrToInterface(dbServer.Tags), types.String),
					"type":                     llx.StringDataPtr(dbServer.Type),
					"properties":               llx.DictData(properties),
					"sslEnforcement":           llx.BoolDataPtr(sslEnforcement),
					"minimalTlsVersion":        llx.StringDataPtr(minimalTlsVersion),
					"publicNetworkAccess":      llx.StringDataPtr(publicNetworkAccess),
					"infrastructureEncryption": llx.BoolDataPtr(infrastructureEncryption),
					"version":                  llx.StringDataPtr(version),
					"backupRetentionDays":      llx.IntData(backupRetentionDays),
					"geoRedundantBackup":       llx.StringData(geoRedundantBackup),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzurePostgresServer)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionPostgreSqlServiceFlexibleServer) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionPostgreSqlServiceFlexibleServerInternal struct {
	cachePrimaryKeyURI           string
	cacheGeoBackupKeyURI         string
	cacheSystemData              any
	cacheUserAssignedIdentityIds []string
	cacheDelegatedSubnetId       *string
	cachePrivateDnsZoneId        *string
	cacheSourceServerId          *string
}

// delegatedSubnet resolves the subnet a privately-accessible server is injected
// into. Null on a server using public access with firewall rules.
func (a *mqlAzureSubscriptionPostgreSqlServiceFlexibleServer) delegatedSubnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	return resolveDelegatedSubnet(a.MqlRuntime, a.cacheDelegatedSubnetId, &a.DelegatedSubnet)
}

// privateDnsZone resolves the private DNS zone the server registers in. Null
// unless the server is deployed with private access.
func (a *mqlAzureSubscriptionPostgreSqlServiceFlexibleServer) privateDnsZone() (*mqlAzureSubscriptionDnsServicePrivateZone, error) {
	return resolveServerPrivateDnsZone(a.MqlRuntime, a.cachePrivateDnsZoneId, &a.PrivateDnsZone)
}

// sourceServer resolves the server this one was created from. Null on a server
// that is neither a replica nor a restore.
func (a *mqlAzureSubscriptionPostgreSqlServiceFlexibleServer) sourceServer() (*mqlAzureSubscriptionPostgreSqlServiceFlexibleServer, error) {
	if a.cacheSourceServerId == nil || *a.cacheSourceServerId == "" {
		a.SourceServer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.postgreSqlService.flexibleServer",
		map[string]*llx.RawData{"id": llx.StringDataPtr(a.cacheSourceServerId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionPostgreSqlServiceFlexibleServer), nil
}

// resolveDelegatedSubnet is shared by the resources that model virtual network
// injection identically: the PostgreSQL and MySQL flexible servers, and Azure
// NetApp Files volumes.
func resolveDelegatedSubnet(runtime *plugin.Runtime, id *string, field *plugin.TValue[*mqlAzureSubscriptionNetworkServiceSubnet]) (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	if id == nil || *id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "azure.subscription.networkService.subnet",
		map[string]*llx.RawData{"id": llx.StringDataPtr(id)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceSubnet), nil
}

// resolveServerPrivateDnsZone is shared by the PostgreSQL and MySQL flexible
// servers.
func resolveServerPrivateDnsZone(runtime *plugin.Runtime, id *string, field *plugin.TValue[*mqlAzureSubscriptionDnsServicePrivateZone]) (*mqlAzureSubscriptionDnsServicePrivateZone, error) {
	if id == nil || *id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "azure.subscription.dnsService.privateZone",
		map[string]*llx.RawData{"id": llx.StringDataPtr(id)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionDnsServicePrivateZone), nil
}

func (a *mqlAzureSubscriptionPostgreSqlServiceFlexibleServer) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionPostgreSqlServiceFlexibleServer) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

func (a *mqlAzureSubscriptionPostgreSqlService) flexibleServers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	dbClient, err := flexible.NewServersClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := dbClient.NewListBySubscriptionPager(&flexible.ServersClientListBySubscriptionOptions{})
	res := []any{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, dbServer := range page.Value {
			if dbServer == nil {
				continue
			}
			properties := make(map[string](any))

			data, err := json.Marshal(dbServer.Properties)
			if err != nil {
				return nil, err
			}

			err = json.Unmarshal([]byte(data), &properties)
			if err != nil {
				return nil, err
			}

			var version string
			if dbServer.Properties != nil && dbServer.Properties.Version != nil {
				version = string(*dbServer.Properties.Version)
			}

			var activeDirectoryAuth, passwordAuth, dataEncryptionType *string
			var primaryEncryptionKeyStatus, geoBackupEncryptionKeyStatus, publicNetworkAccess *string
			if dbServer.Properties != nil {
				if dbServer.Properties.AuthConfig != nil {
					activeDirectoryAuth = (*string)(dbServer.Properties.AuthConfig.ActiveDirectoryAuth)
					passwordAuth = (*string)(dbServer.Properties.AuthConfig.PasswordAuth)
				}
				if dbServer.Properties.DataEncryption != nil {
					dataEncryptionType = (*string)(dbServer.Properties.DataEncryption.Type)
					primaryEncryptionKeyStatus = (*string)(dbServer.Properties.DataEncryption.PrimaryEncryptionKeyStatus)
					geoBackupEncryptionKeyStatus = (*string)(dbServer.Properties.DataEncryption.GeoBackupEncryptionKeyStatus)
				}
				if dbServer.Properties.Network != nil {
					publicNetworkAccess = (*string)(dbServer.Properties.Network.PublicNetworkAccess)
				}
			}

			var fullVersion, administratorLogin, state, availabilityZone *string
			var haMode, haState, standbyAvailabilityZone *string
			var storageAutoGrow, storageTier, storageType *string
			var storageSizeGB *int32
			var replicationRole, entraTenantId *string
			var delegatedSubnetId, privateDnsZoneId, sourceServerId *string
			var maintenanceWindow any
			var maintenanceCustomWindow *string
			var maintenanceDayOfWeek, maintenanceStartHour, maintenanceStartMinute *int32
			if p := dbServer.Properties; p != nil {
				// Azure splits the engine version across two properties: version
				// carries the major ("16") and minorVersion only the minor ("14").
				// Publishing minorVersion on its own reports a PostgreSQL 16.14
				// server as "14", which reads as PostgreSQL 14 -- the wrong major
				// release, and older than what is actually running.
				fullVersion = postgresFullVersion(stringEnumPtr(p.Version), p.MinorVersion)
				administratorLogin = p.AdministratorLogin
				state = stringEnumPtr(p.State)
				availabilityZone = p.AvailabilityZone
				sourceServerId = p.SourceServerResourceID
				replicationRole = stringEnumPtr(p.ReplicationRole)
				if ha := p.HighAvailability; ha != nil {
					haMode = stringEnumPtr(ha.Mode)
					haState = stringEnumPtr(ha.State)
					standbyAvailabilityZone = ha.StandbyAvailabilityZone
				}
				if st := p.Storage; st != nil {
					storageAutoGrow = stringEnumPtr(st.AutoGrow)
					storageTier = stringEnumPtr(st.Tier)
					storageType = stringEnumPtr(st.Type)
					storageSizeGB = st.StorageSizeGB
				}
				if n := p.Network; n != nil {
					delegatedSubnetId = n.DelegatedSubnetResourceID
					privateDnsZoneId = n.PrivateDNSZoneArmResourceID
				}
				if ac := p.AuthConfig; ac != nil {
					entraTenantId = ac.TenantID
				}
				maintenanceWindow, err = convert.JsonToDict(p.MaintenanceWindow)
				if err != nil {
					return nil, err
				}
				mw := orZero(p.MaintenanceWindow)
				maintenanceCustomWindow = mw.CustomWindow
				maintenanceDayOfWeek = mw.DayOfWeek
				maintenanceStartHour = mw.StartHour
				maintenanceStartMinute = mw.StartMinute
			}

			var backupRetentionDays int64
			var geoRedundantBackup string
			if dbServer.Properties != nil && dbServer.Properties.Backup != nil {
				if dbServer.Properties.Backup.BackupRetentionDays != nil {
					backupRetentionDays = int64(*dbServer.Properties.Backup.BackupRetentionDays)
				}
				if dbServer.Properties.Backup.GeoRedundantBackup != nil {
					geoRedundantBackup = string(*dbServer.Properties.Backup.GeoRedundantBackup)
				}
			}

			var identityType, identityPrincipalId, identityTenantId *string
			var userAssignedIdentityIds []string
			if dbServer.Identity != nil {
				identityType = cosmosEnumStrPtr(dbServer.Identity.Type)
				identityPrincipalId = dbServer.Identity.PrincipalID
				identityTenantId = dbServer.Identity.TenantID
				userAssignedIdentityIds = sortedUserAssignedIdentityIDs(dbServer.Identity.UserAssignedIdentities)
			}

			maintenanceSchedule, err := maintenanceWindowRefData(a.MqlRuntime, convert.ToValue(dbServer.ID),
				maintenanceCustomWindow, maintenanceDayOfWeek, maintenanceStartHour, maintenanceStartMinute)
			if err != nil {
				return nil, err
			}

			mqlAzurePostgresServer, err := CreateResource(a.MqlRuntime, "azure.subscription.postgreSqlService.flexibleServer",
				map[string]*llx.RawData{
					"id":                           llx.StringDataPtr(dbServer.ID),
					"name":                         llx.StringDataPtr(dbServer.Name),
					"location":                     llx.StringDataPtr(dbServer.Location),
					"tags":                         llx.MapData(convert.PtrMapStrToInterface(dbServer.Tags), types.String),
					"type":                         llx.StringDataPtr(dbServer.Type),
					"properties":                   llx.DictData(properties),
					"version":                      llx.StringData(version),
					"activeDirectoryAuth":          llx.StringDataPtr(activeDirectoryAuth),
					"passwordAuth":                 llx.StringDataPtr(passwordAuth),
					"dataEncryptionType":           llx.StringDataPtr(dataEncryptionType),
					"primaryEncryptionKeyStatus":   llx.StringDataPtr(primaryEncryptionKeyStatus),
					"geoBackupEncryptionKeyStatus": llx.StringDataPtr(geoBackupEncryptionKeyStatus),
					"publicNetworkAccess":          llx.StringDataPtr(publicNetworkAccess),
					"backupRetentionDays":          llx.IntData(backupRetentionDays),
					"geoRedundantBackup":           llx.StringData(geoRedundantBackup),
					"identityType":                 llx.StringDataPtr(identityType),
					"principalId":                  llx.StringDataPtr(identityPrincipalId),
					"tenantId":                     llx.StringDataPtr(identityTenantId),

					"fullVersion":             llx.StringDataPtr(fullVersion),
					"administratorLogin":      llx.StringDataPtr(administratorLogin),
					"state":                   llx.StringDataPtr(state),
					"availabilityZone":        llx.StringDataPtr(availabilityZone),
					"highAvailabilityMode":    llx.StringDataPtr(haMode),
					"highAvailabilityState":   llx.StringDataPtr(haState),
					"standbyAvailabilityZone": llx.StringDataPtr(standbyAvailabilityZone),
					"storageSizeGB":           llx.IntDataPtr(storageSizeGB),
					"storageAutoGrow":         llx.StringDataPtr(storageAutoGrow),
					"storageTier":             llx.StringDataPtr(storageTier),
					"storageType":             llx.StringDataPtr(storageType),
					"replicationRole":         llx.StringDataPtr(replicationRole),
					"entraTenantId":           llx.StringDataPtr(entraTenantId),
					"maintenanceWindow":       llx.DictData(maintenanceWindow),
					"maintenanceSchedule":     maintenanceSchedule,
				})
			if err != nil {
				return nil, err
			}
			mqlServer := mqlAzurePostgresServer.(*mqlAzureSubscriptionPostgreSqlServiceFlexibleServer)
			mqlServer.cacheUserAssignedIdentityIds = userAssignedIdentityIds
			mqlServer.cacheDelegatedSubnetId = delegatedSubnetId
			mqlServer.cachePrivateDnsZoneId = privateDnsZoneId
			mqlServer.cacheSourceServerId = sourceServerId
			if dbServer.Properties != nil && dbServer.Properties.DataEncryption != nil {
				if dbServer.Properties.DataEncryption.PrimaryKeyURI != nil {
					mqlServer.cachePrimaryKeyURI = *dbServer.Properties.DataEncryption.PrimaryKeyURI
				}
				if dbServer.Properties.DataEncryption.GeoBackupKeyURI != nil {
					mqlServer.cacheGeoBackupKeyURI = *dbServer.Properties.DataEncryption.GeoBackupKeyURI
				}
			}
			sysData, err := convert.JsonToDict(dbServer.SystemData)
			if err != nil {
				return nil, err
			}
			mqlServer.cacheSystemData = sysData
			res = append(res, mqlAzurePostgresServer)
		}
	}

	return keepTagMatches(a.MqlRuntime, res), nil
}

func (a *mqlAzureSubscriptionPostgreSqlServiceServer) databases() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	server, err := resourceID.Component("servers")
	if err != nil {
		return nil, err
	}

	dbDatabaseClient, err := postgresql.NewDatabasesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := dbDatabaseClient.NewListByServerPager(resourceID.ResourceGroup, server, &postgresql.DatabasesClientListByServerOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			mqlAzureDatabase, err := CreateResource(a.MqlRuntime, "azure.subscription.postgreSqlService.database",
				map[string]*llx.RawData{
					"id":        llx.StringDataPtr(entry.ID),
					"name":      llx.StringDataPtr(entry.Name),
					"type":      llx.StringDataPtr(entry.Type),
					"charset":   llx.StringDataPtr(orZero(entry.Properties).Charset),
					"collation": llx.StringDataPtr(orZero(entry.Properties).Collation),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzureDatabase)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionPostgreSqlServiceFlexibleServer) databases() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	server, err := resourceID.Component("flexibleServers")
	if err != nil {
		return nil, err
	}

	dbDatabaseClient, err := flexible.NewDatabasesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := dbDatabaseClient.NewListByServerPager(resourceID.ResourceGroup, server, &flexible.DatabasesClientListByServerOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			mqlAzureDatabase, err := CreateResource(a.MqlRuntime, "azure.subscription.postgreSqlService.database",
				map[string]*llx.RawData{
					"id":        llx.StringDataPtr(entry.ID),
					"name":      llx.StringDataPtr(entry.Name),
					"type":      llx.StringDataPtr(entry.Type),
					"charset":   llx.StringDataPtr(orZero(entry.Properties).Charset),
					"collation": llx.StringDataPtr(orZero(entry.Properties).Collation),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzureDatabase)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionPostgreSqlServiceServer) firewallRules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	server, err := resourceID.Component("servers")
	if err != nil {
		return nil, err
	}
	dbFirewallClient, err := postgresql.NewFirewallRulesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := dbFirewallClient.NewListByServerPager(resourceID.ResourceGroup, server, &postgresql.FirewallRulesClientListByServerOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			mqlFireWallRule, err := CreateResource(a.MqlRuntime, "azure.subscription.sqlService.firewallrule",
				map[string]*llx.RawData{
					"id":             llx.StringDataPtr(entry.ID),
					"name":           llx.StringDataPtr(entry.Name),
					"type":           llx.StringDataPtr(entry.Type),
					"startIpAddress": llx.StringDataPtr(orZero(entry.Properties).StartIPAddress),
					"endIpAddress":   llx.StringDataPtr(orZero(entry.Properties).EndIPAddress),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlFireWallRule)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionPostgreSqlServiceFlexibleServer) firewallRules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	server, err := resourceID.Component("flexibleServers")
	if err != nil {
		return nil, err
	}
	dbFirewallClient, err := flexible.NewFirewallRulesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := dbFirewallClient.NewListByServerPager(resourceID.ResourceGroup, server, &flexible.FirewallRulesClientListByServerOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			mqlFireWallRule, err := CreateResource(a.MqlRuntime, "azure.subscription.sqlService.firewallrule",
				map[string]*llx.RawData{
					"id":             llx.StringDataPtr(entry.ID),
					"name":           llx.StringDataPtr(entry.Name),
					"type":           llx.StringDataPtr(entry.Type),
					"startIpAddress": llx.StringDataPtr(orZero(entry.Properties).StartIPAddress),
					"endIpAddress":   llx.StringDataPtr(orZero(entry.Properties).EndIPAddress),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlFireWallRule)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionPostgreSqlServiceServer) configuration() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	server, err := resourceID.Component("servers")
	if err != nil {
		return nil, err
	}
	dbConfClient, err := postgresql.NewConfigurationsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := dbConfClient.NewListByServerPager(resourceID.ResourceGroup, server, &postgresql.ConfigurationsClientListByServerOptions{})
	res := []any{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			mqlAzureConfiguration, err := CreateResource(a.MqlRuntime, "azure.subscription.sqlService.configuration",
				map[string]*llx.RawData{
					"id":            llx.StringDataPtr(entry.ID),
					"name":          llx.StringDataPtr(entry.Name),
					"type":          llx.StringDataPtr(entry.Type),
					"value":         llx.StringDataPtr(orZero(entry.Properties).Value),
					"description":   llx.StringDataPtr(orZero(entry.Properties).Description),
					"defaultValue":  llx.StringDataPtr(orZero(entry.Properties).DefaultValue),
					"dataType":      llx.StringDataPtr(orZero(entry.Properties).DataType),
					"allowedValues": llx.StringDataPtr(orZero(entry.Properties).AllowedValues),
					"source":        llx.StringDataPtr(orZero(entry.Properties).Source),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzureConfiguration)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionPostgreSqlServiceFlexibleServer) configuration() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	server, err := resourceID.Component("flexibleServers")
	if err != nil {
		return nil, err
	}
	dbConfClient, err := flexible.NewConfigurationsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := dbConfClient.NewListByServerPager(resourceID.ResourceGroup, server, &flexible.ConfigurationsClientListByServerOptions{})
	res := []any{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			mqlAzureConfiguration, err := CreateResource(a.MqlRuntime, "azure.subscription.sqlService.configuration",
				map[string]*llx.RawData{
					"id":            llx.StringDataPtr(entry.ID),
					"name":          llx.StringDataPtr(entry.Name),
					"type":          llx.StringDataPtr(entry.Type),
					"value":         llx.StringDataPtr(orZero(entry.Properties).Value),
					"description":   llx.StringDataPtr(orZero(entry.Properties).Description),
					"defaultValue":  llx.StringDataPtr(orZero(entry.Properties).DefaultValue),
					"dataType":      llx.StringDataPtr((*string)(orZero(entry.Properties).DataType)),
					"allowedValues": llx.StringDataPtr(orZero(entry.Properties).AllowedValues),
					"source":        llx.StringDataPtr(orZero(entry.Properties).Source),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzureConfiguration)
		}
	}

	return res, nil
}

func initAzureSubscriptionPostgreSqlServiceServer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil && ids.id != "" {
			args["id"] = llx.StringData(ids.id)
		}
	}

	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch azure postgresql server")
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	res, err := NewResource(runtime, "azure.subscription.postgreSqlService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, nil, err
	}
	postgreSql := res.(*mqlAzureSubscriptionPostgreSqlService)
	servers := postgreSql.GetServers()
	if servers.Error != nil {
		return nil, nil, servers.Error
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	for _, entry := range servers.Data {
		vm := entry.(*mqlAzureSubscriptionPostgreSqlServiceServer)
		if vm.Id.Data == id {
			return args, vm, nil
		}
	}

	return nil, nil, errors.New("azure postgresql server does not exist")
}

func initAzureSubscriptionPostgreSqlServiceFlexibleServer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil && ids.id != "" {
			args["id"] = llx.StringData(ids.id)
		}
	}

	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch azure postgresql flexible server")
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	res, err := NewResource(runtime, "azure.subscription.postgreSqlService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, nil, err
	}
	postgreSql := res.(*mqlAzureSubscriptionPostgreSqlService)
	servers := postgreSql.GetFlexibleServers()
	if servers.Error != nil {
		return nil, nil, servers.Error
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	for _, entry := range servers.Data {
		vm := entry.(*mqlAzureSubscriptionPostgreSqlServiceFlexibleServer)
		if vm.Id.Data == id {
			return args, vm, nil
		}
	}

	if filtered := tagFilteredOut(runtime, ResourceAzureSubscriptionPostgreSqlServiceFlexibleServer, id); filtered != nil {
		return args, filtered, nil
	}

	return nil, nil, errors.New("azure postgresql flexible server does not exist")
}

func (a *mqlAzureSubscriptionPostgreSqlServiceFlexibleServer) dataEncryptionKey() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	if a.cachePrimaryKeyURI == "" {
		a.DataEncryptionKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, a.cachePrimaryKeyURI)
}

func (a *mqlAzureSubscriptionPostgreSqlServiceFlexibleServer) geoBackupEncryptionKey() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	if a.cacheGeoBackupKeyURI == "" {
		a.GeoBackupEncryptionKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, a.cacheGeoBackupKeyURI)
}

// privateEndpointConnections lists private endpoint connections attached to the flexible server.
func (a *mqlAzureSubscriptionPostgreSqlServiceFlexibleServer) privateEndpointConnections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	rid, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	server, err := rid.Component("flexibleServers")
	if err != nil {
		return nil, err
	}
	client, err := flexible.NewPrivateEndpointConnectionsClient(rid.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListByServerPager(rid.ResourceGroup, server, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		// The shared helper seeds every declared field, including ipAddresses.
		// Hand-rolling the args map here left ipAddresses out entirely, so it
		// was unset rather than empty on every connection.
		conns, err := azurePrivateEndpointConnectionsToMql(a.MqlRuntime, page.Value)
		if err != nil {
			return nil, err
		}
		res = append(res, conns...)
	}
	return res, nil
}

// threatProtectionState fetches the Microsoft Defender for Cloud Advanced Threat Protection state.
func (a *mqlAzureSubscriptionPostgreSqlServiceFlexibleServer) threatProtectionState() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return "", err
	}
	server, err := resourceID.Component("flexibleServers")
	if err != nil {
		return "", err
	}

	client, err := flexible.NewAdvancedThreatProtectionSettingsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return "", err
	}
	resp, err := client.Get(ctx, resourceID.ResourceGroup, server, flexible.ThreatProtectionNameDefault, nil)
	if err != nil {
		return "", err
	}
	if resp.Properties == nil || resp.Properties.State == nil {
		return "", nil
	}
	return string(*resp.Properties.State), nil
}

// postgresFullVersion joins Azure's split engine version into the single
// "<major>.<minor>" string the fullVersion field documents.
//
// Returns nil when Azure reports only a major version, which the schema
// describes as an empty fullVersion, so a caller cannot mistake a partial
// answer for a complete one.
func postgresFullVersion(version, minorVersion *string) *string {
	if minorVersion == nil || *minorVersion == "" {
		return nil
	}
	if version == nil || *version == "" {
		return nil
	}
	full := *version + "." + *minorVersion
	return &full
}
