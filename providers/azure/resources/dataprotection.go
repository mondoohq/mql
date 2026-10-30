// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dataprotection/armdataprotection/v4"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionDataProtectionServiceBackupVaultInternal struct {
	cacheSystemData              any
	cacheEncryptionIdentityId    string
	cacheUserAssignedIdentityIds []string
}

func (a *mqlAzureSubscriptionDataProtectionService) id() (string, error) {
	return "azure.subscription.dataProtectionService/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionDataProtectionService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionDataProtectionServiceBackupVault) id() (string, error) {
	return a.Id.Data, nil
}

func initAzureSubscriptionDataProtectionServiceBackupVault(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromServiceList(runtime, args,
		ResourceAzureSubscriptionDataProtectionService,
		func(s *mqlAzureSubscriptionDataProtectionService) *plugin.TValue[[]any] { return s.GetBackupVaults() },
		ResourceAzureSubscriptionDataProtectionServiceBackupVault)
}

func (a *mqlAzureSubscriptionDataProtectionServiceBackupVault) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionDataProtectionServiceBackupVault) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

func (a *mqlAzureSubscriptionDataProtectionService) backupVaults() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	client, err := armdataprotection.NewBackupVaultsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewGetInSubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, vault := range page.Value {
			if vault == nil {
				continue
			}
			mqlVault, err := createBackupVaultResource(a.MqlRuntime, vault)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlVault)
		}
	}
	return res, nil
}

// backupVaultStorageRedundancy maps each of the vault's storage settings to the
// datastore it governs, so a query can ask for the redundancy of the vault
// store without walking a list.
//
// A setting missing either half is skipped rather than being recorded under an
// empty key, which would read as a datastore called "" with a redundancy of "".
func backupVaultStorageRedundancy(settings []*armdataprotection.StorageSetting) map[string]any {
	res := map[string]any{}
	for _, setting := range settings {
		if setting == nil {
			continue
		}
		datastore := enumString(setting.DatastoreType)
		redundancy := enumString(setting.Type)
		if datastore == "" || redundancy == "" {
			continue
		}
		res[datastore] = redundancy
	}
	return res
}

func createBackupVaultResource(runtime *plugin.Runtime, vault *armdataprotection.BackupVaultResource) (*mqlAzureSubscriptionDataProtectionServiceBackupVault, error) {
	props := vault.Properties
	if props == nil {
		props = &armdataprotection.BackupVault{}
	}

	identity, err := convert.JsonToDict(vault.Identity)
	if err != nil {
		return nil, err
	}

	vaultIdentity := orZero(vault.Identity)
	userAssignedIdentityIds := sortedUserAssignedIdentityIDs(vaultIdentity.UserAssignedIdentities)

	var softDeleteState, immutabilityState string
	var softDeleteRetentionDays float64
	var encryptionState, infrastructureEncryption, encryptionKeyUri string
	var encryptionKeyIdentityType, encryptionKeyIdentityId string
	if sec := props.SecuritySettings; sec != nil {
		if sd := sec.SoftDeleteSettings; sd != nil {
			softDeleteState = enumString(sd.State)
			softDeleteRetentionDays = convert.ToValue(sd.RetentionDurationInDays)
		}
		if im := sec.ImmutabilitySettings; im != nil {
			immutabilityState = enumString(im.State)
		}
		if enc := sec.EncryptionSettings; enc != nil {
			encryptionState = enumString(enc.State)
			infrastructureEncryption = enumString(enc.InfrastructureEncryption)
			if enc.KeyVaultProperties != nil {
				encryptionKeyUri = convert.ToValue(enc.KeyVaultProperties.KeyURI)
			}
			if enc.KekIdentity != nil {
				encryptionKeyIdentityType = enumString(enc.KekIdentity.IdentityType)
				encryptionKeyIdentityId = convert.ToValue(enc.KekIdentity.IdentityID)
			}
		}
	}

	var crossRegionRestoreState, crossSubscriptionRestoreState string
	if fs := props.FeatureSettings; fs != nil {
		if fs.CrossRegionRestoreSettings != nil {
			crossRegionRestoreState = enumString(fs.CrossRegionRestoreSettings.State)
		}
		if fs.CrossSubscriptionRestoreSettings != nil {
			crossSubscriptionRestoreState = enumString(fs.CrossSubscriptionRestoreSettings.State)
		}
	}

	var alertsForAllJobFailures string
	if props.MonitoringSettings != nil && props.MonitoringSettings.AzureMonitorAlertSettings != nil {
		alertsForAllJobFailures = enumString(props.MonitoringSettings.AzureMonitorAlertSettings.AlertsForAllJobFailures)
	}

	resourceIdentity, err := resourceIdentityData(runtime, convert.ToValue(vault.ID), userAssignedIdentityIds,
		identityType(vaultIdentity.Type), identityPrincipalId(vaultIdentity.PrincipalID), identityTenantId(vaultIdentity.TenantID))
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(runtime, ResourceAzureSubscriptionDataProtectionServiceBackupVault,
		map[string]*llx.RawData{
			"id":                              llx.StringDataPtr(vault.ID),
			"name":                            llx.StringDataPtr(vault.Name),
			"location":                        llx.StringDataPtr(vault.Location),
			"type":                            llx.StringDataPtr(vault.Type),
			"tags":                            llx.MapData(convert.PtrMapStrToInterface(vault.Tags), types.String),
			"etag":                            llx.StringDataPtr(vault.ETag),
			"provisioningState":               llx.StringData(enumString(props.ProvisioningState)),
			"identity":                        llx.DictData(identity),
			"resourceIdentity":                resourceIdentity,
			"softDeleteState":                 llx.StringData(softDeleteState),
			"softDeleteRetentionPeriodInDays": llx.FloatData(softDeleteRetentionDays),
			"immutabilityState":               llx.StringData(immutabilityState),
			"encryptionState":                 llx.StringData(encryptionState),
			"infrastructureEncryption":        llx.StringData(infrastructureEncryption),
			"encryptionKeyUri":                llx.StringData(encryptionKeyUri),
			"encryptionKeyIdentityType":       llx.StringData(encryptionKeyIdentityType),
			"crossRegionRestoreState":         llx.StringData(crossRegionRestoreState),
			"crossSubscriptionRestoreState":   llx.StringData(crossSubscriptionRestoreState),
			"replicatedRegions":               llx.ArrayData(strPtrSliceToAny(props.ReplicatedRegions), types.String),
			"storageRedundancy":               llx.MapData(backupVaultStorageRedundancy(props.StorageSettings), types.String),
			"bcdrSecurityLevel":               llx.StringData(enumString(props.BcdrSecurityLevel)),
			"secureScore":                     llx.StringData(enumString(props.SecureScore)),
			"isVaultProtectedByResourceGuard": llx.BoolDataPtr(props.IsVaultProtectedByResourceGuard),
			"resourceGuardOperationRequests":  llx.ArrayData(strPtrSliceToAny(props.ResourceGuardOperationRequests), types.String),
			"alertsForAllJobFailures":         llx.StringData(alertsForAllJobFailures),
		})
	if err != nil {
		return nil, err
	}

	mqlVault := resource.(*mqlAzureSubscriptionDataProtectionServiceBackupVault)
	mqlVault.cacheEncryptionIdentityId = encryptionKeyIdentityId
	mqlVault.cacheUserAssignedIdentityIds = userAssignedIdentityIds

	sysData, err := convert.JsonToDict(vault.SystemData)
	if err != nil {
		return nil, err
	}
	mqlVault.cacheSystemData = sysData

	return mqlVault, nil
}

func (a *mqlAzureSubscriptionDataProtectionServiceBackupVault) encryptionKey() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	if a.EncryptionKeyUri.Data == "" {
		a.EncryptionKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, a.EncryptionKeyUri.Data)
}

func (a *mqlAzureSubscriptionDataProtectionServiceBackupVault) encryptionKeyIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	if a.cacheEncryptionIdentityId == "" {
		a.EncryptionKeyIdentity.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.managedIdentity",
		map[string]*llx.RawData{"__id": llx.StringData(a.cacheEncryptionIdentityId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionManagedIdentity), nil
}
