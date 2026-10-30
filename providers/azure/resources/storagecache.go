// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storagecache/armstoragecache/v4"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionStorageCacheServiceAmlFilesystemInternal struct {
	cacheSystemData              any
	cacheSubnetId                *string
	cacheKeyVaultId              string
	cacheHsmContainerId          string
	cacheHsmLoggingContainerId   string
	cacheUserAssignedIdentityIds []string
}

func (a *mqlAzureSubscriptionStorageCacheService) id() (string, error) {
	return "azure.subscription.storageCacheService/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionStorageCacheService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionStorageCacheServiceAmlFilesystem) id() (string, error) {
	return a.Id.Data, nil
}

func initAzureSubscriptionStorageCacheServiceAmlFilesystem(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromServiceList(runtime, args,
		ResourceAzureSubscriptionStorageCacheService,
		func(s *mqlAzureSubscriptionStorageCacheService) *plugin.TValue[[]any] { return s.GetAmlFilesystems() },
		ResourceAzureSubscriptionStorageCacheServiceAmlFilesystem)
}

func (a *mqlAzureSubscriptionStorageCacheServiceAmlFilesystem) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionStorageCacheServiceAmlFilesystem) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

func (a *mqlAzureSubscriptionStorageCacheService) amlFilesystems() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	client, err := armstoragecache.NewAmlFilesystemsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, fs := range page.Value {
			if fs == nil {
				continue
			}
			mqlFs, err := createAmlFilesystemResource(a.MqlRuntime, fs)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlFs)
		}
	}
	return res, nil
}

// amlKeyEncryptionKey reads the customer-managed key reference out of a file
// system's encryption settings, returning the key URL and the resource ID of
// the vault holding it.
//
// Every level is optional, and a file system encrypted with the platform key
// omits all of them. That absence is reported as empty rather than being
// treated as a key that failed to read, since it is what says the file system
// is not using a customer-managed key at all.
func amlKeyEncryptionKey(settings *armstoragecache.AmlFilesystemEncryptionSettings) (keyURL string, sourceVaultID string) {
	if settings == nil || settings.KeyEncryptionKey == nil {
		return "", ""
	}
	keyURL = convert.ToValue(settings.KeyEncryptionKey.KeyURL)
	if settings.KeyEncryptionKey.SourceVault != nil {
		sourceVaultID = convert.ToValue(settings.KeyEncryptionKey.SourceVault.ID)
	}
	return keyURL, sourceVaultID
}

func createAmlFilesystemResource(runtime *plugin.Runtime, fs *armstoragecache.AmlFilesystem) (*mqlAzureSubscriptionStorageCacheServiceAmlFilesystem, error) {
	props := fs.Properties
	if props == nil {
		props = &armstoragecache.AmlFilesystemProperties{}
	}

	identity, err := convert.JsonToDict(fs.Identity)
	if err != nil {
		return nil, err
	}

	fsIdentity := orZero(fs.Identity)
	userAssignedIdentityIds := sortedUserAssignedIdentityIDs(fsIdentity.UserAssignedIdentities)

	var skuName string
	if fs.SKU != nil {
		skuName = convert.ToValue(fs.SKU.Name)
	}

	var healthState, healthStatusCode, healthStatusDescription string
	if props.Health != nil {
		healthState = enumString(props.Health.State)
		healthStatusCode = convert.ToValue(props.Health.StatusCode)
		healthStatusDescription = convert.ToValue(props.Health.StatusDescription)
	}

	keyEncryptionKeyUrl, keyVaultId := amlKeyEncryptionKey(props.EncryptionSettings)

	// The squash UID and GID are carried as pointers, not dereferenced. 0 is
	// the root id, so a file system with no squash mapping configured would
	// otherwise report that root maps to root -- which reads as "squashing is
	// in place and does nothing", the opposite of the truth.
	var squashMode, squashNidLists, squashStatus string
	var squashUid, squashGid *int64
	if props.RootSquashSettings != nil {
		squashMode = enumString(props.RootSquashSettings.Mode)
		squashNidLists = convert.ToValue(props.RootSquashSettings.NoSquashNidLists)
		squashStatus = convert.ToValue(props.RootSquashSettings.Status)
		squashUid = props.RootSquashSettings.SquashUID
		squashGid = props.RootSquashSettings.SquashGID
	}

	var hsmContainerId, hsmLoggingContainerId, hsmImportPrefix string
	hsmImportPrefixesInitial := []any{}
	if props.Hsm != nil && props.Hsm.Settings != nil {
		hsmContainerId = convert.ToValue(props.Hsm.Settings.Container)
		hsmLoggingContainerId = convert.ToValue(props.Hsm.Settings.LoggingContainer)
		hsmImportPrefix = convert.ToValue(props.Hsm.Settings.ImportPrefix)
		hsmImportPrefixesInitial = strPtrSliceToAny(props.Hsm.Settings.ImportPrefixesInitial)
	}

	var maintenanceDay, maintenanceTime string
	if props.MaintenanceWindow != nil {
		maintenanceDay = enumString(props.MaintenanceWindow.DayOfWeek)
		maintenanceTime = convert.ToValue(props.MaintenanceWindow.TimeOfDayUTC)
	}

	var lustreVersion, mgsAddress, mountCommand string
	if props.ClientInfo != nil {
		lustreVersion = convert.ToValue(props.ClientInfo.LustreVersion)
		mgsAddress = convert.ToValue(props.ClientInfo.MgsAddress)
		mountCommand = convert.ToValue(props.ClientInfo.MountCommand)
	}

	resourceIdentity, err := resourceIdentityData(runtime, convert.ToValue(fs.ID), userAssignedIdentityIds,
		identityType(fsIdentity.Type), identityPrincipalId(fsIdentity.PrincipalID), identityTenantId(fsIdentity.TenantID))
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(runtime, ResourceAzureSubscriptionStorageCacheServiceAmlFilesystem,
		map[string]*llx.RawData{
			"id":                            llx.StringDataPtr(fs.ID),
			"name":                          llx.StringDataPtr(fs.Name),
			"location":                      llx.StringDataPtr(fs.Location),
			"type":                          llx.StringDataPtr(fs.Type),
			"tags":                          llx.MapData(convert.PtrMapStrToInterface(fs.Tags), types.String),
			"zones":                         llx.ArrayData(strPtrSliceToAny(fs.Zones), types.String),
			"skuName":                       llx.StringData(skuName),
			"provisioningState":             llx.StringData(enumString(props.ProvisioningState)),
			"identity":                      llx.DictData(identity),
			"resourceIdentity":              resourceIdentity,
			"storageCapacityTiB":            llx.FloatDataPtr(props.StorageCapacityTiB),
			"currentStorageCapacityTiB":     llx.FloatDataPtr(props.CurrentStorageCapacityTiB),
			"throughputProvisionedMbps":     llx.IntDataPtr(props.ThroughputProvisionedMBps),
			"clusterUuid":                   llx.StringDataPtr(props.ClusterUUID),
			"healthState":                   llx.StringData(healthState),
			"healthStatusCode":              llx.StringData(healthStatusCode),
			"healthStatusDescription":       llx.StringData(healthStatusDescription),
			"keyEncryptionKeyUrl":           llx.StringData(keyEncryptionKeyUrl),
			"rootSquashMode":                llx.StringData(squashMode),
			"rootSquashNoSquashNidLists":    llx.StringData(squashNidLists),
			"rootSquashUid":                 llx.IntDataPtr(squashUid),
			"rootSquashGid":                 llx.IntDataPtr(squashGid),
			"rootSquashStatus":              llx.StringData(squashStatus),
			"hsmImportPrefix":               llx.StringData(hsmImportPrefix),
			"hsmImportPrefixesInitial":      llx.ArrayData(hsmImportPrefixesInitial, types.String),
			"maintenanceWindowDayOfWeek":    llx.StringData(maintenanceDay),
			"maintenanceWindowTimeOfDayUtc": llx.StringData(maintenanceTime),
			"lustreVersion":                 llx.StringData(lustreVersion),
			"mgsAddress":                    llx.StringData(mgsAddress),
			"mountCommand":                  llx.StringData(mountCommand),
		})
	if err != nil {
		return nil, err
	}

	mqlFs := resource.(*mqlAzureSubscriptionStorageCacheServiceAmlFilesystem)
	mqlFs.cacheSubnetId = props.FilesystemSubnet
	mqlFs.cacheKeyVaultId = keyVaultId
	mqlFs.cacheHsmContainerId = hsmContainerId
	mqlFs.cacheHsmLoggingContainerId = hsmLoggingContainerId
	mqlFs.cacheUserAssignedIdentityIds = userAssignedIdentityIds

	sysData, err := convert.JsonToDict(fs.SystemData)
	if err != nil {
		return nil, err
	}
	mqlFs.cacheSystemData = sysData

	return mqlFs, nil
}

func (a *mqlAzureSubscriptionStorageCacheServiceAmlFilesystem) keyEncryptionKey() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	if a.KeyEncryptionKeyUrl.Data == "" {
		a.KeyEncryptionKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, a.KeyEncryptionKeyUrl.Data)
}

func (a *mqlAzureSubscriptionStorageCacheServiceAmlFilesystem) keyEncryptionKeyVault() (*mqlAzureSubscriptionKeyVaultServiceVault, error) {
	if a.cacheKeyVaultId == "" {
		a.KeyEncryptionKeyVault.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionKeyVaultServiceVault,
		map[string]*llx.RawData{"id": llx.StringData(a.cacheKeyVaultId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionKeyVaultServiceVault), nil
}

func (a *mqlAzureSubscriptionStorageCacheServiceAmlFilesystem) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	return resolveDelegatedSubnet(a.MqlRuntime, a.cacheSubnetId, &a.Subnet)
}

func (a *mqlAzureSubscriptionStorageCacheServiceAmlFilesystem) hsmContainer() (*mqlAzureSubscriptionStorageServiceAccountContainer, error) {
	return resolveBlobContainer(a.MqlRuntime, a.cacheHsmContainerId, &a.HsmContainer)
}

func (a *mqlAzureSubscriptionStorageCacheServiceAmlFilesystem) hsmLoggingContainer() (*mqlAzureSubscriptionStorageServiceAccountContainer, error) {
	return resolveBlobContainer(a.MqlRuntime, a.cacheHsmLoggingContainerId, &a.HsmLoggingContainer)
}

// resolveBlobContainer turns a blob container's ARM resource ID into the
// container resource. A file system with no blob integration reports no
// container ID at all, which is a null reference rather than a failed one.
func resolveBlobContainer(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlAzureSubscriptionStorageServiceAccountContainer]) (*mqlAzureSubscriptionStorageServiceAccountContainer, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "azure.subscription.storageService.account.container",
		map[string]*llx.RawData{"id": llx.StringData(id)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionStorageServiceAccountContainer), nil
}
