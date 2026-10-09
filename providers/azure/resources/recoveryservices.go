// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservices/v3"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservicesbackup/v5"
	subscriptions "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions/v2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
	"golang.org/x/sync/errgroup"
)

type mqlAzureSubscriptionRecoveryServicesServiceVaultInternal struct {
	cacheSecuritySettings        *armrecoveryservices.SecuritySettings
	cacheEncryption              *armrecoveryservices.VaultPropertiesEncryption
	cacheMonitoringSettings      *armrecoveryservices.MonitoringSettings
	cacheRedundancySettings      *armrecoveryservices.VaultPropertiesRedundancySettings
	cachePrivateEndpointConn     []*armrecoveryservices.PrivateEndpointConnectionVaultProperties
	cacheSystemData              any
	cacheUserAssignedIdentityIds []string
}

type mqlAzureSubscriptionRecoveryServicesServiceDeletedVaultInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionRecoveryServicesService) id() (string, error) {
	return "azure.subscription.recoveryServicesService/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionRecoveryServicesService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionRecoveryServicesServiceVault) id() (string, error) {
	return a.Id.Data, nil
}

func initAzureSubscriptionRecoveryServicesServiceVault(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil && ids.id != "" {
			args["id"] = llx.StringData(ids.id)
		}
	}

	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch azure recovery services vault")
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	res, err := NewResource(runtime, "azure.subscription.recoveryServicesService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, nil, err
	}
	svc := res.(*mqlAzureSubscriptionRecoveryServicesService)
	list := svc.GetVaults()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	for _, entry := range list.Data {
		vault := entry.(*mqlAzureSubscriptionRecoveryServicesServiceVault)
		if vault.Id.Data == id {
			return args, vault, nil
		}
	}

	if filtered := tagFilteredOut(runtime, ResourceAzureSubscriptionRecoveryServicesServiceVault, id); filtered != nil {
		return args, filtered, nil
	}

	return nil, nil, errors.New("azure recovery services vault does not exist")
}

func (a *mqlAzureSubscriptionRecoveryServicesService) vaults() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := armrecoveryservices.NewVaultsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListBySubscriptionIDPager(nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, vault := range page.Value {
			if vault == nil {
				continue
			}
			// The list-by-subscription API returns vault basics but not nested
			// SecuritySettings/Encryption/RedundancySettings. Fetch each vault
			// individually so the security-relevant detail is populated.
			if vault.ID != nil {
				if rid, err := ParseResourceID(*vault.ID); err == nil {
					if detail, err := client.Get(ctx, rid.ResourceGroup, *vault.Name, nil); err == nil {
						vault = &detail.Vault
					}
				}
			}
			mqlVault, err := createVaultResource(a.MqlRuntime, vault)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlVault)
		}
	}
	return keepTagMatches(a.MqlRuntime, res), nil
}

// deletedVaults lists soft-deleted Recovery Services vaults awaiting purge.
// The Azure API only lists deleted vaults per region, so the subscription's
// physical regions are enumerated and queried concurrently.
func (a *mqlAzureSubscriptionRecoveryServicesService) deletedVaults() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	subClient, err := subscriptions.NewClient(token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	var locations []string
	locPager := subClient.NewListLocationsPager(subId, nil)
	for locPager.More() {
		page, err := locPager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, loc := range page.Value {
			if loc == nil || loc.Name == nil {
				continue
			}
			// Skip logical regions (e.g. edge zones); deleted vaults live in
			// physical regions only.
			if loc.Metadata != nil && loc.Metadata.RegionType != nil &&
				*loc.Metadata.RegionType != subscriptions.RegionTypePhysical {
				continue
			}
			locations = append(locations, *loc.Name)
		}
	}

	client, err := armrecoveryservices.NewDeletedVaultsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	// Each deleted vault is paired with the region it was queried from, since
	// the DeletedVault payload itself carries no location.
	type deletedVaultEntry struct {
		vault    *armrecoveryservices.DeletedVault
		location string
	}
	var mu sync.Mutex
	var deleted []deletedVaultEntry
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(10)
	for _, location := range locations {
		g.Go(func() error {
			pager := client.NewListBySubscriptionIDPager(location, nil)
			for pager.More() {
				page, err := pager.NextPage(gctx)
				if err != nil {
					// One unreachable or access-denied region shouldn't fail the
					// whole listing; log it and continue with the rest.
					//
					// Most of them are neither. The location list is every region
					// the subscription can see, and Recovery Services is not
					// deployed in all of them: staging and edge regions answer
					// NoRegisteredProviderFound. That is an expected absence, so
					// it stays out of the warning stream a real access problem
					// needs to stand out in.
					if azureProviderNotInRegion(err) {
						log.Debug().Err(err).Str("location", location).Msg("recovery services is not available in region")
						return nil
					}
					log.Warn().Err(err).Str("location", location).Msg("could not list deleted recovery services vaults in region")
					return nil
				}
				mu.Lock()
				for _, dv := range page.Value {
					if dv == nil {
						continue
					}
					deleted = append(deleted, deletedVaultEntry{vault: dv, location: location})
				}
				mu.Unlock()
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	var res []any
	for _, entry := range deleted {
		mqlDeletedVault, err := createDeletedVaultResource(a.MqlRuntime, entry.vault, entry.location)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlDeletedVault)
	}
	return res, nil
}

func createDeletedVaultResource(runtime *plugin.Runtime, dv *armrecoveryservices.DeletedVault, location string) (*mqlAzureSubscriptionRecoveryServicesServiceDeletedVault, error) {
	var vaultResourceId string
	var vaultDeletionTime *time.Time
	var purgeAt *time.Time
	if dv.Properties != nil {
		if dv.Properties.VaultID != nil {
			vaultResourceId = *dv.Properties.VaultID
		}
		vaultDeletionTime = dv.Properties.VaultDeletionTime
		purgeAt = dv.Properties.PurgeAt
	}

	resource, err := CreateResource(runtime, ResourceAzureSubscriptionRecoveryServicesServiceDeletedVault,
		map[string]*llx.RawData{
			"id":                llx.StringDataPtr(dv.ID),
			"name":              llx.StringDataPtr(dv.Name),
			"location":          llx.StringData(location),
			"type":              llx.StringDataPtr(dv.Type),
			"vaultResourceId":   llx.StringData(vaultResourceId),
			"vaultDeletionTime": llx.TimeDataPtr(vaultDeletionTime),
			"purgeAt":           llx.TimeDataPtr(purgeAt),
		})
	if err != nil {
		return nil, err
	}

	mqlDeletedVault := resource.(*mqlAzureSubscriptionRecoveryServicesServiceDeletedVault)

	sysData, err := convert.JsonToDict(dv.SystemData)
	if err != nil {
		return nil, err
	}
	mqlDeletedVault.cacheSystemData = sysData

	return mqlDeletedVault, nil
}

func (a *mqlAzureSubscriptionRecoveryServicesServiceDeletedVault) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionRecoveryServicesServiceDeletedVault) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// vaultCrossSubscriptionRestoreState reads the vault's cross-subscription
// restore state out of the nested restore settings. Every level of the nesting
// is optional in the ARM payload, and an absent setting is not the same as a
// disabled one: Azure treats the absence as enabled, so it reports as empty
// rather than being folded into "Disabled".
func vaultCrossSubscriptionRestoreState(props *armrecoveryservices.VaultProperties) string {
	if props == nil || props.RestoreSettings == nil ||
		props.RestoreSettings.CrossSubscriptionRestoreSettings == nil ||
		props.RestoreSettings.CrossSubscriptionRestoreSettings.CrossSubscriptionRestoreState == nil {
		return ""
	}
	return string(*props.RestoreSettings.CrossSubscriptionRestoreSettings.CrossSubscriptionRestoreState)
}

func createVaultResource(runtime *plugin.Runtime, vault *armrecoveryservices.Vault) (*mqlAzureSubscriptionRecoveryServicesServiceVault, error) {
	props := vault.Properties
	if props == nil {
		props = &armrecoveryservices.VaultProperties{}
	}

	identity, err := convert.JsonToDict(vault.Identity)
	if err != nil {
		return nil, err
	}

	vaultIdentity := orZero(vault.Identity)
	userAssignedIdentityIds := sortedUserAssignedIdentityIDs(vaultIdentity.UserAssignedIdentities)

	var skuName string
	if vault.SKU != nil && vault.SKU.Name != nil {
		skuName = string(*vault.SKU.Name)
	}

	var provisioningState string
	if props.ProvisioningState != nil {
		provisioningState = *props.ProvisioningState
	}

	var publicNetworkAccess string
	if props.PublicNetworkAccess != nil {
		publicNetworkAccess = string(*props.PublicNetworkAccess)
	}

	var backupStorageVersion string
	if props.BackupStorageVersion != nil {
		backupStorageVersion = string(*props.BackupStorageVersion)
	}

	var privateEndpointStateForBackup string
	if props.PrivateEndpointStateForBackup != nil {
		privateEndpointStateForBackup = string(*props.PrivateEndpointStateForBackup)
	}

	var privateEndpointStateForSiteRecovery string
	if props.PrivateEndpointStateForSiteRecovery != nil {
		privateEndpointStateForSiteRecovery = string(*props.PrivateEndpointStateForSiteRecovery)
	}

	var secureScore string
	if props.SecureScore != nil {
		secureScore = string(*props.SecureScore)
	}

	var costManagementGranularityLevel string
	if props.CostManagementSettings != nil && props.CostManagementSettings.GranularityLevel != nil {
		costManagementGranularityLevel = string(*props.CostManagementSettings.GranularityLevel)
	}

	var regionOfChoiceStatus string
	if props.RegionOfChoiceSettings != nil && props.RegionOfChoiceSettings.Status != nil {
		regionOfChoiceStatus = string(*props.RegionOfChoiceSettings.Status)
	}

	resourceIdentity, err := resourceIdentityData(runtime, convert.ToValue(vault.ID), userAssignedIdentityIds,
		identityType(vaultIdentity.Type), identityPrincipalId(vaultIdentity.PrincipalID), identityTenantId(vaultIdentity.TenantID))
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(runtime, ResourceAzureSubscriptionRecoveryServicesServiceVault,
		map[string]*llx.RawData{
			"id":                                  llx.StringDataPtr(vault.ID),
			"name":                                llx.StringDataPtr(vault.Name),
			"location":                            llx.StringDataPtr(vault.Location),
			"type":                                llx.StringDataPtr(vault.Type),
			"tags":                                llx.MapData(convert.PtrMapStrToInterface(vault.Tags), types.String),
			"identity":                            llx.DictData(identity),
			"resourceIdentity":                    resourceIdentity,
			"skuName":                             llx.StringData(skuName),
			"provisioningState":                   llx.StringData(provisioningState),
			"publicNetworkAccess":                 llx.StringData(publicNetworkAccess),
			"backupStorageVersion":                llx.StringData(backupStorageVersion),
			"privateEndpointStateForBackup":       llx.StringData(privateEndpointStateForBackup),
			"privateEndpointStateForSiteRecovery": llx.StringData(privateEndpointStateForSiteRecovery),
			"secureScore":                         llx.StringData(secureScore),
			"costManagementGranularityLevel":      llx.StringData(costManagementGranularityLevel),
			"regionOfChoiceStatus":                llx.StringData(regionOfChoiceStatus),
			"crossSubscriptionRestoreState":       llx.StringData(vaultCrossSubscriptionRestoreState(props)),
		})
	if err != nil {
		return nil, err
	}

	mqlVault := resource.(*mqlAzureSubscriptionRecoveryServicesServiceVault)
	mqlVault.cacheSecuritySettings = props.SecuritySettings
	mqlVault.cacheEncryption = props.Encryption
	mqlVault.cacheMonitoringSettings = props.MonitoringSettings
	mqlVault.cacheRedundancySettings = props.RedundancySettings
	mqlVault.cachePrivateEndpointConn = props.PrivateEndpointConnections
	mqlVault.cacheUserAssignedIdentityIds = userAssignedIdentityIds

	sysData, err := convert.JsonToDict(vault.SystemData)
	if err != nil {
		return nil, err
	}
	mqlVault.cacheSystemData = sysData

	return mqlVault, nil
}

func (a *mqlAzureSubscriptionRecoveryServicesServiceVault) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// userAssignedIdentities returns the typed user-assigned managed identities of the vault.
func (a *mqlAzureSubscriptionRecoveryServicesServiceVault) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

// securitySettings builds the security settings sub-resource from cached data.
func (a *mqlAzureSubscriptionRecoveryServicesServiceVault) securitySettings() (*mqlAzureSubscriptionRecoveryServicesServiceVaultSecuritySettings, error) {
	ss := a.cacheSecuritySettings
	if ss == nil {
		a.SecuritySettings.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	var softDeleteState string
	var softDeleteRetentionPeriodInDays int64
	var enhancedSecurityState string
	if ss.SoftDeleteSettings != nil {
		if ss.SoftDeleteSettings.SoftDeleteState != nil {
			softDeleteState = string(*ss.SoftDeleteSettings.SoftDeleteState)
		}
		if ss.SoftDeleteSettings.SoftDeleteRetentionPeriodInDays != nil {
			softDeleteRetentionPeriodInDays = int64(*ss.SoftDeleteSettings.SoftDeleteRetentionPeriodInDays)
		}
		if ss.SoftDeleteSettings.EnhancedSecurityState != nil {
			enhancedSecurityState = string(*ss.SoftDeleteSettings.EnhancedSecurityState)
		}
	}

	var immutabilityState string
	if ss.ImmutabilitySettings != nil && ss.ImmutabilitySettings.State != nil {
		immutabilityState = string(*ss.ImmutabilitySettings.State)
	}

	var multiUserAuthorization string
	if ss.MultiUserAuthorization != nil {
		multiUserAuthorization = string(*ss.MultiUserAuthorization)
	}

	var sourceScanConfigurationState string
	if ss.SourceScanConfiguration != nil && ss.SourceScanConfiguration.State != nil {
		sourceScanConfigurationState = string(*ss.SourceScanConfiguration.State)
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionRecoveryServicesServiceVaultSecuritySettings,
		map[string]*llx.RawData{
			"id":                              llx.StringData(a.Id.Data + "/securitySettings"),
			"softDeleteState":                 llx.StringData(softDeleteState),
			"softDeleteRetentionPeriodInDays": llx.IntData(softDeleteRetentionPeriodInDays),
			"enhancedSecurityState":           llx.StringData(enhancedSecurityState),
			"immutabilityState":               llx.StringData(immutabilityState),
			"multiUserAuthorization":          llx.StringData(multiUserAuthorization),
			"sourceScanConfigurationState":    llx.StringData(sourceScanConfigurationState),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionRecoveryServicesServiceVaultSecuritySettings), nil
}

func (a *mqlAzureSubscriptionRecoveryServicesServiceVaultSecuritySettings) id() (string, error) {
	return a.Id.Data, nil
}

// encryption builds the encryption sub-resource from cached data.
func (a *mqlAzureSubscriptionRecoveryServicesServiceVault) encryption() (*mqlAzureSubscriptionRecoveryServicesServiceVaultEncryption, error) {
	enc := a.cacheEncryption
	if enc == nil {
		a.Encryption.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	var infrastructureEncryption string
	if enc.InfrastructureEncryption != nil {
		infrastructureEncryption = string(*enc.InfrastructureEncryption)
	}

	var keyVaultKeyUri string
	if enc.KeyVaultProperties != nil && enc.KeyVaultProperties.KeyURI != nil {
		keyVaultKeyUri = *enc.KeyVaultProperties.KeyURI
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionRecoveryServicesServiceVaultEncryption,
		map[string]*llx.RawData{
			"id":                       llx.StringData(a.Id.Data + "/encryption"),
			"infrastructureEncryption": llx.StringData(infrastructureEncryption),
			"keyVaultKeyUri":           llx.StringData(keyVaultKeyUri),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionRecoveryServicesServiceVaultEncryption), nil
}

func (a *mqlAzureSubscriptionRecoveryServicesServiceVaultEncryption) id() (string, error) {
	return a.Id.Data, nil
}

// key returns a typed reference to the Key Vault key used for CMK encryption.
func (a *mqlAzureSubscriptionRecoveryServicesServiceVaultEncryption) key() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	keyURI := a.KeyVaultKeyUri.Data
	if keyURI == "" {
		a.Key.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, keyURI)
}

// monitoringSettings builds the monitoring settings sub-resource from cached data.
func (a *mqlAzureSubscriptionRecoveryServicesServiceVault) monitoringSettings() (*mqlAzureSubscriptionRecoveryServicesServiceVaultMonitoringSettings, error) {
	ms := a.cacheMonitoringSettings
	if ms == nil {
		a.MonitoringSettings.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	var alertsForAllFailoverIssues, alertsForAllJobFailures, alertsForAllReplicationIssues string
	if ms.AzureMonitorAlertSettings != nil {
		if ms.AzureMonitorAlertSettings.AlertsForAllFailoverIssues != nil {
			alertsForAllFailoverIssues = string(*ms.AzureMonitorAlertSettings.AlertsForAllFailoverIssues)
		}
		if ms.AzureMonitorAlertSettings.AlertsForAllJobFailures != nil {
			alertsForAllJobFailures = string(*ms.AzureMonitorAlertSettings.AlertsForAllJobFailures)
		}
		if ms.AzureMonitorAlertSettings.AlertsForAllReplicationIssues != nil {
			alertsForAllReplicationIssues = string(*ms.AzureMonitorAlertSettings.AlertsForAllReplicationIssues)
		}
	}

	var alertsForCriticalOperations, emailNotificationsForSiteRecovery string
	if ms.ClassicAlertSettings != nil {
		if ms.ClassicAlertSettings.AlertsForCriticalOperations != nil {
			alertsForCriticalOperations = string(*ms.ClassicAlertSettings.AlertsForCriticalOperations)
		}
		if ms.ClassicAlertSettings.EmailNotificationsForSiteRecovery != nil {
			emailNotificationsForSiteRecovery = string(*ms.ClassicAlertSettings.EmailNotificationsForSiteRecovery)
		}
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionRecoveryServicesServiceVaultMonitoringSettings,
		map[string]*llx.RawData{
			"id":                                llx.StringData(a.Id.Data + "/monitoringSettings"),
			"alertsForAllFailoverIssues":        llx.StringData(alertsForAllFailoverIssues),
			"alertsForAllJobFailures":           llx.StringData(alertsForAllJobFailures),
			"alertsForAllReplicationIssues":     llx.StringData(alertsForAllReplicationIssues),
			"alertsForCriticalOperations":       llx.StringData(alertsForCriticalOperations),
			"emailNotificationsForSiteRecovery": llx.StringData(emailNotificationsForSiteRecovery),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionRecoveryServicesServiceVaultMonitoringSettings), nil
}

func (a *mqlAzureSubscriptionRecoveryServicesServiceVaultMonitoringSettings) id() (string, error) {
	return a.Id.Data, nil
}

// redundancySettings builds the redundancy settings sub-resource from cached data.
func (a *mqlAzureSubscriptionRecoveryServicesServiceVault) redundancySettings() (*mqlAzureSubscriptionRecoveryServicesServiceVaultRedundancySettings, error) {
	rs := a.cacheRedundancySettings
	if rs == nil {
		a.RedundancySettings.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	var storageRedundancy string
	if rs.StandardTierStorageRedundancy != nil {
		storageRedundancy = string(*rs.StandardTierStorageRedundancy)
	}

	var crossRegionRestore string
	if rs.CrossRegionRestore != nil {
		crossRegionRestore = string(*rs.CrossRegionRestore)
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionRecoveryServicesServiceVaultRedundancySettings,
		map[string]*llx.RawData{
			"id":                 llx.StringData(a.Id.Data + "/redundancySettings"),
			"storageRedundancy":  llx.StringData(storageRedundancy),
			"crossRegionRestore": llx.StringData(crossRegionRestore),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionRecoveryServicesServiceVaultRedundancySettings), nil
}

func (a *mqlAzureSubscriptionRecoveryServicesServiceVaultRedundancySettings) id() (string, error) {
	return a.Id.Data, nil
}

// privateEndpointConnections builds the shared private endpoint connection resources.
func (a *mqlAzureSubscriptionRecoveryServicesServiceVault) privateEndpointConnections() ([]any, error) {
	var res []any
	for _, pec := range a.cachePrivateEndpointConn {
		if pec == nil {
			continue
		}

		var name, resType string
		if pec.ID != nil {
			connResourceID, err := ParseResourceID(*pec.ID)
			if err == nil {
				if nameComp, err := connResourceID.Component("privateEndpointConnections"); err == nil {
					name = nameComp
				}
				if connResourceID.Provider != "" {
					resType = connResourceID.Provider + "/vaults/privateEndpointConnections"
				}
			}
			if name == "" {
				parts := strings.Split(*pec.ID, "/")
				if len(parts) > 0 {
					name = parts[len(parts)-1]
				}
			}
		}
		if resType == "" {
			resType = "Microsoft.RecoveryServices/vaults/privateEndpointConnections"
		}

		var pecPrivateEndpointID string
		pecArgs := map[string]*llx.RawData{
			"__id": llx.StringDataPtr(pec.ID),
			"id":   llx.StringDataPtr(pec.ID),
			"name": llx.StringData(name),
			"type": llx.StringData(resType),
		}

		if pec.Properties != nil {
			props := pec.Properties
			propsMap, err := convert.JsonToDict(props)
			if err != nil {
				return nil, err
			}
			pecArgs["properties"] = llx.DictData(propsMap)

			if props.PrivateEndpoint != nil {
				pecPrivateEndpointID = convert.ToValue(props.PrivateEndpoint.ID)
			}
			if props.PrivateLinkServiceConnectionState != nil {
				stateRes, err := newPrivateLinkServiceConnectionState(a.MqlRuntime, convert.ToValue(pec.ID),
					stringEnumPtr(props.PrivateLinkServiceConnectionState.ActionsRequired),
					props.PrivateLinkServiceConnectionState.Description,
					stringEnumPtr(props.PrivateLinkServiceConnectionState.Status))
				if err != nil {
					return nil, err
				}
				pecArgs["privateLinkServiceConnectionState"] = llx.ResourceData(stateRes, ResourceAzureSubscriptionPrivateEndpointConnectionConnectionState)
			}
			if props.ProvisioningState != nil {
				pecArgs["provisioningState"] = llx.StringData(string(*props.ProvisioningState))
			}
		}

		mqlRes, err := newAzurePrivateEndpointConnection(a.MqlRuntime, pecArgs, pecPrivateEndpointID)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRes)
	}
	return res, nil
}

// backupConfig fetches the backup vault configuration (soft delete, storage type).
func (a *mqlAzureSubscriptionRecoveryServicesServiceVault) backupConfig() (*mqlAzureSubscriptionRecoveryServicesServiceVaultBackupConfig, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	vaultName, err := resourceID.Component("vaults")
	if err != nil {
		return nil, err
	}

	client, err := armrecoveryservicesbackup.NewBackupResourceVaultConfigsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	resp, err := client.Get(ctx, vaultName, resourceID.ResourceGroup, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && (respErr.StatusCode == http.StatusForbidden || respErr.StatusCode == http.StatusNotFound) {
			a.BackupConfig.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	props := resp.Properties
	if props == nil {
		a.BackupConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	var softDeleteFeatureState string
	if props.SoftDeleteFeatureState != nil {
		softDeleteFeatureState = string(*props.SoftDeleteFeatureState)
	}

	var softDeleteRetentionDays int64
	if props.SoftDeleteRetentionPeriodInDays != nil {
		softDeleteRetentionDays = int64(*props.SoftDeleteRetentionPeriodInDays)
	}

	var enhancedSecurityState string
	if props.EnhancedSecurityState != nil {
		enhancedSecurityState = string(*props.EnhancedSecurityState)
	}

	var storageType string
	if props.StorageType != nil {
		storageType = string(*props.StorageType)
	}

	var storageTypeState string
	if props.StorageTypeState != nil {
		storageTypeState = string(*props.StorageTypeState)
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionRecoveryServicesServiceVaultBackupConfig,
		map[string]*llx.RawData{
			"id":                              llx.StringData(id + "/backupConfig"),
			"softDeleteFeatureState":          llx.StringData(softDeleteFeatureState),
			"softDeleteRetentionPeriodInDays": llx.IntData(softDeleteRetentionDays),
			"enhancedSecurityState":           llx.StringData(enhancedSecurityState),
			"storageType":                     llx.StringData(storageType),
			"storageTypeState":                llx.StringData(storageTypeState),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionRecoveryServicesServiceVaultBackupConfig), nil
}

func (a *mqlAzureSubscriptionRecoveryServicesServiceVaultBackupConfig) id() (string, error) {
	return a.Id.Data, nil
}

// vaultChildLocationAndTags answers the location and tags for a child of a
// recovery services vault.
//
// Backup policies and protected items are ARM proxy resources: the API omits
// location and tags from both the list and the get response, and a PUT that
// sets either has them stripped from the stored resource. Azure applies a tag
// written against a policy's resource ID to the vault instead.
//
// The child still lives in the vault's region, so fall back to that rather
// than reporting an unknown location. Tags stay null: an empty map asserts the
// resource carries no tags, and that is a claim the API never made, so a
// policy requiring a tag would fail on every policy in the tenant while a
// policy exempting by tag would exempt none of them.
func vaultChildLocationAndTags(vaultLocation *plugin.TValue[string], location *string, tags map[string]*string) (*llx.RawData, *llx.RawData) {
	locationData := llx.NilData
	switch {
	case location != nil && *location != "":
		locationData = llx.StringDataPtr(location)
	case vaultLocation != nil && vaultLocation.Error == nil &&
		vaultLocation.State&plugin.StateIsNull == 0 && vaultLocation.Data != "":
		locationData = llx.StringData(vaultLocation.Data)
	}

	tagsData := llx.NilData
	if len(tags) > 0 {
		tagsData = llx.MapData(convert.PtrMapStrToInterface(tags), types.String)
	}

	return locationData, tagsData
}

// backupPolicies fetches all backup policies in the vault.
func (a *mqlAzureSubscriptionRecoveryServicesServiceVault) backupPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	vaultName, err := resourceID.Component("vaults")
	if err != nil {
		return nil, err
	}

	client, err := armrecoveryservicesbackup.NewBackupPoliciesClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(vaultName, resourceID.ResourceGroup, nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, policy := range page.Value {
			if policy == nil {
				continue
			}

			properties, err := convert.JsonToDict(policy.Properties)
			if err != nil {
				return nil, err
			}

			location, tags := vaultChildLocationAndTags(a.GetLocation(), policy.Location, policy.Tags)

			mqlPolicy, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionRecoveryServicesServiceVaultBackupPolicy,
				map[string]*llx.RawData{
					"id":         llx.StringDataPtr(policy.ID),
					"name":       llx.StringDataPtr(policy.Name),
					"location":   location,
					"tags":       tags,
					"type":       llx.StringDataPtr(policy.Type),
					"properties": llx.DictData(properties),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPolicy)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionRecoveryServicesServiceVaultBackupPolicy) id() (string, error) {
	return a.Id.Data, nil
}

// protectedItems fetches all protected (backed-up) items in the vault.
func (a *mqlAzureSubscriptionRecoveryServicesServiceVault) protectedItems() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	vaultName, err := resourceID.Component("vaults")
	if err != nil {
		return nil, err
	}

	client, err := armrecoveryservicesbackup.NewBackupProtectedItemsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(vaultName, resourceID.ResourceGroup, nil)
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, item := range page.Value {
			if item == nil {
				continue
			}

			properties, err := convert.JsonToDict(item.Properties)
			if err != nil {
				return nil, err
			}

			location, tags := vaultChildLocationAndTags(a.GetLocation(), item.Location, item.Tags)

			mqlItem, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionRecoveryServicesServiceVaultProtectedItem,
				map[string]*llx.RawData{
					"id":         llx.StringDataPtr(item.ID),
					"name":       llx.StringDataPtr(item.Name),
					"location":   location,
					"tags":       tags,
					"type":       llx.StringDataPtr(item.Type),
					"properties": llx.DictData(properties),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlItem)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionRecoveryServicesServiceVaultProtectedItem) id() (string, error) {
	return a.Id.Data, nil
}
