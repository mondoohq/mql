// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"

	mysql "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysql"

	flexible "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers/v2"
)

func (a *mqlAzureSubscriptionMySqlService) id() (string, error) {
	return "azure.subscription.mysql/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionMySqlService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionMySqlServiceServer) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionMySqlServiceFlexibleServer) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionMySqlServiceDatabase) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionMySqlService) servers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	dbClient, err := mysql.NewServersClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := dbClient.NewListPager(&mysql.ServersClientListOptions{})
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
			properties, err := convert.JsonToDict(dbServer.Properties)
			if err != nil {
				return nil, err
			}

			var sslEnforcement *bool
			var minimalTlsVersion *string
			var publicNetworkAccess *string
			var infrastructureEncryption *bool
			var version *string
			var backupRetentionDays int64
			var geoRedundantBackup string
			if dbServer.Properties != nil {
				if dbServer.Properties.SSLEnforcement != nil {
					v := *dbServer.Properties.SSLEnforcement == mysql.SSLEnforcementEnumEnabled
					sslEnforcement = &v
				}
				minimalTlsVersion = (*string)(dbServer.Properties.MinimalTLSVersion)
				publicNetworkAccess = (*string)(dbServer.Properties.PublicNetworkAccess)
				if dbServer.Properties.InfrastructureEncryption != nil {
					v := *dbServer.Properties.InfrastructureEncryption == mysql.InfrastructureEncryptionEnabled
					infrastructureEncryption = &v
				}
				version = (*string)(dbServer.Properties.Version)
				if dbServer.Properties.StorageProfile != nil {
					if dbServer.Properties.StorageProfile.BackupRetentionDays != nil {
						backupRetentionDays = int64(*dbServer.Properties.StorageProfile.BackupRetentionDays)
					}
					if dbServer.Properties.StorageProfile.GeoRedundantBackup != nil {
						geoRedundantBackup = string(*dbServer.Properties.StorageProfile.GeoRedundantBackup)
					}
				}
			}

			mqlAzureDbServer, err := CreateResource(a.MqlRuntime, "azure.subscription.mySqlService.server",
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
			res = append(res, mqlAzureDbServer)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionMySqlService) flexibleServers() ([]any, error) {
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
	pager := dbClient.NewListPager(&flexible.ServersClientListOptions{})
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
			properties, err := convert.JsonToDict(dbServer.Properties)
			if err != nil {
				return nil, err
			}

			var version string
			if dbServer.Properties != nil && dbServer.Properties.Version != nil {
				version = string(*dbServer.Properties.Version)
			}

			var publicNetworkAccess string
			if dbServer.Properties != nil {
				if dbServer.Properties.Network != nil && dbServer.Properties.Network.PublicNetworkAccess != nil {
					publicNetworkAccess = string(*dbServer.Properties.Network.PublicNetworkAccess)
				}
			}

			var dataEncryptionType string
			if dbServer.Properties != nil && dbServer.Properties.DataEncryption != nil {
				if dbServer.Properties.DataEncryption.Type != nil {
					dataEncryptionType = string(*dbServer.Properties.DataEncryption.Type)
				}
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

			var haMode, haState string
			if dbServer.Properties != nil && dbServer.Properties.HighAvailability != nil {
				if dbServer.Properties.HighAvailability.Mode != nil {
					haMode = string(*dbServer.Properties.HighAvailability.Mode)
				}
				if dbServer.Properties.HighAvailability.State != nil {
					haState = string(*dbServer.Properties.HighAvailability.State)
				}
			}

			var identityType, identityPrincipalId, identityTenantId *string
			var userAssignedIdentityIds []string
			if dbServer.Identity != nil {
				identityType = cosmosEnumStrPtr(dbServer.Identity.Type)
				identityPrincipalId = dbServer.Identity.PrincipalID
				identityTenantId = dbServer.Identity.TenantID
				userAssignedIdentityIds = sortedUserAssignedIdentityKeys(dbServer.Identity.UserAssignedIdentities)
			}

			var fullVersion, storageRedundancy, maintenancePatchStrategy *string
			var databasePort, backupIntervalHours *int32
			var storageAutoIoScaling, storageLogOnDisk *bool
			if dbServer.Properties != nil {
				fullVersion = dbServer.Properties.FullVersion
				databasePort = dbServer.Properties.DatabasePort
				if dbServer.Properties.Backup != nil {
					backupIntervalHours = dbServer.Properties.Backup.BackupIntervalHours
				}
				if dbServer.Properties.Storage != nil {
					storageRedundancy = (*string)(dbServer.Properties.Storage.StorageRedundancy)
					if dbServer.Properties.Storage.AutoIoScaling != nil {
						v := *dbServer.Properties.Storage.AutoIoScaling == flexible.EnableStatusEnumEnabled
						storageAutoIoScaling = &v
					}
					if dbServer.Properties.Storage.LogOnDisk != nil {
						v := *dbServer.Properties.Storage.LogOnDisk == flexible.EnableStatusEnumEnabled
						storageLogOnDisk = &v
					}
				}
				if dbServer.Properties.MaintenancePolicy != nil {
					maintenancePatchStrategy = (*string)(dbServer.Properties.MaintenancePolicy.PatchStrategy)
				}
			}

			var administratorLogin, state, availabilityZone, standbyAvailabilityZone *string
			var replicationRole *string
			var delegatedSubnetId, privateDnsZoneId, sourceServerId *string
			var maintenanceWindow any
			var maintenanceCustomWindow *string
			var maintenanceDayOfWeek, maintenanceStartHour, maintenanceStartMinute *int32
			if p := dbServer.Properties; p != nil {
				administratorLogin = p.AdministratorLogin
				state = stringEnumPtr(p.State)
				availabilityZone = p.AvailabilityZone
				replicationRole = stringEnumPtr(p.ReplicationRole)
				sourceServerId = p.SourceServerResourceID
				if ha := p.HighAvailability; ha != nil {
					standbyAvailabilityZone = ha.StandbyAvailabilityZone
				}
				if n := p.Network; n != nil {
					delegatedSubnetId = n.DelegatedSubnetResourceID
					privateDnsZoneId = n.PrivateDNSZoneResourceID
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

			maintenanceSchedule, err := maintenanceWindowRefData(a.MqlRuntime, convert.ToValue(dbServer.ID),
				maintenanceCustomWindow, maintenanceDayOfWeek, maintenanceStartHour, maintenanceStartMinute)
			if err != nil {
				return nil, err
			}

			mqlAzureDbServer, err := CreateResource(a.MqlRuntime, "azure.subscription.mySqlService.flexibleServer",
				map[string]*llx.RawData{
					"id":                       llx.StringDataPtr(dbServer.ID),
					"name":                     llx.StringDataPtr(dbServer.Name),
					"location":                 llx.StringDataPtr(dbServer.Location),
					"tags":                     llx.MapData(convert.PtrMapStrToInterface(dbServer.Tags), types.String),
					"type":                     llx.StringDataPtr(dbServer.Type),
					"properties":               llx.DictData(properties),
					"version":                  llx.StringData(version),
					"publicNetworkAccess":      llx.StringData(publicNetworkAccess),
					"dataEncryptionType":       llx.StringData(dataEncryptionType),
					"backupRetentionDays":      llx.IntData(backupRetentionDays),
					"geoRedundantBackup":       llx.StringData(geoRedundantBackup),
					"highAvailabilityMode":     llx.StringData(haMode),
					"highAvailabilityState":    llx.StringData(haState),
					"identityType":             llx.StringDataPtr(identityType),
					"principalId":              llx.StringDataPtr(identityPrincipalId),
					"tenantId":                 llx.StringDataPtr(identityTenantId),
					"fullVersion":              llx.StringDataPtr(fullVersion),
					"databasePort":             llx.IntDataPtr(databasePort),
					"storageAutoIoScaling":     llx.BoolDataPtr(storageAutoIoScaling),
					"storageLogOnDisk":         llx.BoolDataPtr(storageLogOnDisk),
					"storageRedundancy":        llx.StringDataPtr(storageRedundancy),
					"backupIntervalHours":      llx.IntDataPtr(backupIntervalHours),
					"maintenancePatchStrategy": llx.StringDataPtr(maintenancePatchStrategy),

					"administratorLogin":      llx.StringDataPtr(administratorLogin),
					"state":                   llx.StringDataPtr(state),
					"availabilityZone":        llx.StringDataPtr(availabilityZone),
					"standbyAvailabilityZone": llx.StringDataPtr(standbyAvailabilityZone),
					"replicationRole":         llx.StringDataPtr(replicationRole),
					"maintenanceWindow":       llx.DictData(maintenanceWindow),
					"maintenanceSchedule":     maintenanceSchedule,
				})
			if err != nil {
				return nil, err
			}
			mqlServer := mqlAzureDbServer.(*mqlAzureSubscriptionMySqlServiceFlexibleServer)
			mqlServer.cacheDelegatedSubnetId = delegatedSubnetId
			mqlServer.cachePrivateDnsZoneId = privateDnsZoneId
			mqlServer.cacheSourceServerId = sourceServerId
			mqlServer.cacheUserAssignedIdentityIds = userAssignedIdentityIds
			if dbServer.Properties != nil && dbServer.Properties.DataEncryption != nil {
				if dbServer.Properties.DataEncryption.PrimaryKeyURI != nil {
					mqlServer.cacheDataEncryptionKeyURI = *dbServer.Properties.DataEncryption.PrimaryKeyURI
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
			res = append(res, mqlAzureDbServer)
		}
	}
	return keepTagMatches(a.MqlRuntime, res), nil
}

func (a *mqlAzureSubscriptionMySqlServiceFlexibleServer) sslEnforcement() (bool, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data
	resourceID, err := ParseResourceID(id)
	if err != nil {
		return false, err
	}

	server, err := resourceID.Component("flexibleServers")
	if err != nil {
		return false, err
	}

	dbConfClient, err := flexible.NewConfigurationsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return false, err
	}

	resp, err := dbConfClient.Get(ctx, resourceID.ResourceGroup, server, "require_secure_transport", nil)
	if err != nil {
		// A 404 means the parameter is genuinely absent on this SKU, and MySQL
		// flexible servers enforce SSL by default, so the default is the honest
		// answer there. A 403 is different: it means we were not allowed to
		// look. Reporting the *passing* value for an unread setting would let
		// `flexibleServers.all(sslEnforcement)` pass across a whole fleet with
		// nothing actually verified, so that case must surface as an error.
		var rerr *azcore.ResponseError
		if errors.As(err, &rerr) && rerr.StatusCode == http.StatusNotFound {
			return true, nil
		}
		return false, err
	}

	if resp.Properties != nil && resp.Properties.Value != nil {
		return strings.EqualFold(*resp.Properties.Value, "ON"), nil
	}

	return true, nil
}

func (a *mqlAzureSubscriptionMySqlServiceServer) databases() ([]any, error) {
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

	dbDatabaseClient, err := mysql.NewDatabasesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := dbDatabaseClient.NewListByServerPager(resourceID.ResourceGroup, server, &mysql.DatabasesClientListByServerOptions{})
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
			mqlAzureDatabase, err := CreateResource(a.MqlRuntime, "azure.subscription.mySqlService.database",
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

func (a *mqlAzureSubscriptionMySqlServiceServer) firewallRules() ([]any, error) {
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

	dbFirewallClient, err := mysql.NewFirewallRulesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := dbFirewallClient.NewListByServerPager(resourceID.ResourceGroup, server, &mysql.FirewallRulesClientListByServerOptions{})
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

func (a *mqlAzureSubscriptionMySqlServiceServer) configuration() ([]any, error) {
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

	dbConfClient, err := mysql.NewConfigurationsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := dbConfClient.NewListByServerPager(resourceID.ResourceGroup, server, &mysql.ConfigurationsClientListByServerOptions{})
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

func (a *mqlAzureSubscriptionMySqlServiceFlexibleServer) databases() ([]any, error) {
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
			mqlAzureDatabase, err := CreateResource(a.MqlRuntime, "azure.subscription.mySqlService.database",
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

func (a *mqlAzureSubscriptionMySqlServiceFlexibleServer) firewallRules() ([]any, error) {
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

func (a *mqlAzureSubscriptionMySqlServiceFlexibleServer) configuration() ([]any, error) {
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
					"dataType":      llx.StringDataPtr(orZero(entry.Properties).DataType),
					"allowedValues": llx.StringDataPtr(orZero(entry.Properties).AllowedValues),
					"source":        llx.StringDataPtr((*string)(orZero(entry.Properties).Source)),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAzureConfiguration)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionMySqlServiceFlexibleServerInternal struct {
	cacheDataEncryptionKeyURI    string
	cacheGeoBackupKeyURI         string
	cacheSystemData              any
	cacheUserAssignedIdentityIds []string
	cacheDelegatedSubnetId       *string
	cachePrivateDnsZoneId        *string
	cacheSourceServerId          *string
}

// delegatedSubnet resolves the subnet a privately-accessible server is injected
// into. Null on a server using public access with firewall rules.
func (a *mqlAzureSubscriptionMySqlServiceFlexibleServer) delegatedSubnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	return resolveDelegatedSubnet(a.MqlRuntime, a.cacheDelegatedSubnetId, &a.DelegatedSubnet)
}

// privateDnsZone resolves the private DNS zone the server registers in. Null
// unless the server is deployed with private access.
func (a *mqlAzureSubscriptionMySqlServiceFlexibleServer) privateDnsZone() (*mqlAzureSubscriptionDnsServicePrivateZone, error) {
	return resolveServerPrivateDnsZone(a.MqlRuntime, a.cachePrivateDnsZoneId, &a.PrivateDnsZone)
}

// sourceServer resolves the server this one replicates from. Null on a server
// that is not a replica.
func (a *mqlAzureSubscriptionMySqlServiceFlexibleServer) sourceServer() (*mqlAzureSubscriptionMySqlServiceFlexibleServer, error) {
	if a.cacheSourceServerId == nil || *a.cacheSourceServerId == "" {
		a.SourceServer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.mySqlService.flexibleServer",
		map[string]*llx.RawData{"id": llx.StringDataPtr(a.cacheSourceServerId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionMySqlServiceFlexibleServer), nil
}

func (a *mqlAzureSubscriptionMySqlServiceFlexibleServer) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionMySqlServiceFlexibleServerAdministrator) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionMySqlServiceFlexibleServerAdministratorInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionMySqlServiceFlexibleServerAdministrator) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// threatProtectionState fetches the Microsoft Defender for Cloud advanced threat protection state.
func (a *mqlAzureSubscriptionMySqlServiceFlexibleServer) threatProtectionState() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	resourceID, err := ParseResourceID(a.Id.Data)
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
	resp, err := client.Get(ctx, resourceID.ResourceGroup, server, flexible.AdvancedThreatProtectionNameDefault, nil)
	if err != nil {
		return "", err
	}
	if resp.Properties == nil || resp.Properties.State == nil {
		return "", nil
	}
	return string(*resp.Properties.State), nil
}

func (a *mqlAzureSubscriptionMySqlServiceFlexibleServer) azureAdAdministrators() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	server, err := resourceID.Component("flexibleServers")
	if err != nil {
		return nil, err
	}
	adminClient, err := flexible.NewAzureADAdministratorsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := adminClient.NewListByServerPager(resourceID.ResourceGroup, server, nil)
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
			mqlAdmin, err := CreateResource(a.MqlRuntime, "azure.subscription.mySqlService.flexibleServer.administrator",
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(entry.ID),
					"name":              llx.StringDataPtr(entry.Name),
					"type":              llx.StringDataPtr(entry.Type),
					"administratorType": llx.StringDataPtr((*string)(orZero(entry.Properties).AdministratorType)),
					"login":             llx.StringDataPtr(orZero(entry.Properties).Login),
					"sid":               llx.StringDataPtr(orZero(entry.Properties).Sid),
					"tenantId":          llx.StringDataPtr(orZero(entry.Properties).TenantID),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(entry.SystemData)
			if err != nil {
				return nil, err
			}
			mqlAdmin.(*mqlAzureSubscriptionMySqlServiceFlexibleServerAdministrator).cacheSystemData = sysData
			res = append(res, mqlAdmin)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionMySqlServiceFlexibleServer) privateEndpointConnections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	server, err := resourceID.Component("flexibleServers")
	if err != nil {
		return nil, err
	}
	client, err := flexible.NewPrivateEndpointConnectionsClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	resp, err := client.ListByServer(ctx, resourceID.ResourceGroup, server, nil)
	if err != nil {
		return nil, err
	}
	connections := resp.Value

	// armmysqlflexibleservers/v2 exposes ListByServer as a plain method with no
	// pager, even though the response carries a NextLink -- its postgresql
	// counterpart does ship NewListByServerPager, so this is an SDK asymmetry
	// rather than a non-paginated endpoint. The cursor used to be logged and
	// dropped, which put the truncation in provider stderr where no query result
	// or policy verdict could see it. Follow it instead.
	next := ""
	if resp.NextLink != nil {
		next = *resp.NextLink
	}
	if next != "" {
		err = fetchArmPages(ctx, armTokenFunc(conn), next, "mysql private endpoint connections", func(raw []byte) (string, error) {
			page := flexible.PrivateEndpointConnectionListResult{}
			if err := json.Unmarshal(raw, &page); err != nil {
				return "", err
			}
			connections = append(connections, page.Value...)
			if page.NextLink == nil {
				return "", nil
			}
			return *page.NextLink, nil
		})
		if err != nil {
			return nil, err
		}
	}
	// The shared helper seeds every declared field, including ipAddresses.
	// Hand-rolling the args map here left ipAddresses out entirely, so it was
	// unset rather than empty on every connection. It is handed the accumulated
	// slice rather than resp.Value, so it sees every page and not just the first.
	conns, err := azurePrivateEndpointConnectionsToMql(a.MqlRuntime, connections)
	if err != nil {
		return nil, err
	}
	res = append(res, conns...)
	return res, nil
}

func (a *mqlAzureSubscriptionMySqlServiceFlexibleServer) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

func (a *mqlAzureSubscriptionMySqlServiceFlexibleServer) dataEncryptionKey() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	if a.cacheDataEncryptionKeyURI == "" {
		a.DataEncryptionKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, a.cacheDataEncryptionKeyURI)
}

func (a *mqlAzureSubscriptionMySqlServiceFlexibleServer) geoBackupEncryptionKey() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	if a.cacheGeoBackupKeyURI == "" {
		a.GeoBackupEncryptionKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, a.cacheGeoBackupKeyURI)
}

func initAzureSubscriptionMySqlServiceServer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil && ids.id != "" {
			args["id"] = llx.StringData(ids.id)
		}
	}

	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch azure mysql server")
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	res, err := NewResource(runtime, "azure.subscription.mySqlService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, nil, err
	}
	mysql := res.(*mqlAzureSubscriptionMySqlService)
	servers := mysql.GetServers()
	if servers.Error != nil {
		return nil, nil, servers.Error
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	for _, entry := range servers.Data {
		vm := entry.(*mqlAzureSubscriptionMySqlServiceServer)
		if vm.Id.Data == id {
			return args, vm, nil
		}
	}

	return nil, nil, errors.New("azure mysql server does not exist")
}

func initAzureSubscriptionMySqlServiceFlexibleServer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil && ids.id != "" {
			args["id"] = llx.StringData(ids.id)
		}
	}

	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch azure mysql flexible server")
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	res, err := NewResource(runtime, "azure.subscription.mySqlService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, nil, err
	}
	mysql := res.(*mqlAzureSubscriptionMySqlService)
	servers := mysql.GetFlexibleServers()
	if servers.Error != nil {
		return nil, nil, servers.Error
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	for _, entry := range servers.Data {
		vm := entry.(*mqlAzureSubscriptionMySqlServiceFlexibleServer)
		if vm.Id.Data == id {
			return args, vm, nil
		}
	}

	if filtered := tagFilteredOut(runtime, ResourceAzureSubscriptionMySqlServiceFlexibleServer, id); filtered != nil {
		return args, filtered, nil
	}

	return nil, nil, errors.New("azure mysql flexible server does not exist")
}
