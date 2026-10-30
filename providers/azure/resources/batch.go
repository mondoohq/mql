// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armbatch "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/batch/armbatch/v4"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func initAzureSubscriptionBatchService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionBatchService) id() (string, error) {
	return "azure.subscription.batch/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionBatchServiceAccount) id() (string, error) {
	return a.Id.Data, nil
}

func initAzureSubscriptionBatchServiceAccount(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil && ids.id != "" {
			args["id"] = llx.StringData(ids.id)
		}
	}

	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch azure batch account")
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	res, err := NewResource(runtime, "azure.subscription.batchService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, nil, err
	}
	batchSvc := res.(*mqlAzureSubscriptionBatchService)
	accountList := batchSvc.GetAccounts()
	if accountList.Error != nil {
		return nil, nil, accountList.Error
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	for _, entry := range accountList.Data {
		account := entry.(*mqlAzureSubscriptionBatchServiceAccount)
		if account.Id.Data == id {
			return args, account, nil
		}
	}

	if filtered := tagFilteredOut(runtime, ResourceAzureSubscriptionBatchServiceAccount, id); filtered != nil {
		return args, filtered, nil
	}

	return nil, nil, errors.New("azure batch account does not exist")
}

func (a *mqlAzureSubscriptionBatchService) accounts() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	ctx := context.Background()
	client, err := armbatch.NewAccountClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(&armbatch.AccountClientListOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureNotConfigured(err) {
				log.Warn().Err(err).Msg("could not list azure accounts, returning partial results")
				return keepTagMatches(a.MqlRuntime, res), nil
			}
			return nil, err
		}

		for _, entry := range page.Value {
			if entry == nil {
				continue
			}

			resource, err := batchAccountToMql(a.MqlRuntime, entry)
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}
	}

	return keepTagMatches(a.MqlRuntime, res), nil
}

func createBatchAccountRawData(account *armbatch.Account) (map[string]*llx.RawData, error) {
	principalId := llx.StringData("")
	if account.Identity != nil && account.Identity.PrincipalID != nil {
		principalId = llx.StringData(*account.Identity.PrincipalID)
	}

	propertiesData := llx.NilData
	var (
		accountEndpoint                       = llx.NilData
		provisioningState                     = llx.NilData
		poolAllocationMode                    = llx.NilData
		publicNetworkAccess                   = llx.NilData
		nodeManagementEndpoint                = llx.NilData
		activeJobAndJobScheduleQuota          = llx.NilData
		dedicatedCoreQuota                    = llx.NilData
		dedicatedCoreQuotaPerVmFamilyEnforced = llx.NilData
		dedicatedCoreQuotaPerVmFamily         = llx.NilData
		lowPriorityCoreQuota                  = llx.NilData
		poolQuota                             = llx.NilData
		allowedAuthenticationModes            = llx.NilData
		networkProfile                        = llx.NilData
		privateEndpointConnections            = llx.NilData
	)

	if account.Properties != nil {
		props := account.Properties

		if dict, err := convert.JsonToDict(props); err != nil {
			return nil, err
		} else if dict != nil {
			propertiesData = llx.DictData(dict)
		}

		if props.AccountEndpoint != nil {
			accountEndpoint = llx.StringData(*props.AccountEndpoint)
		}
		if props.ProvisioningState != nil {
			provisioningState = llx.StringData(string(*props.ProvisioningState))
		}
		if props.PoolAllocationMode != nil {
			poolAllocationMode = llx.StringData(string(*props.PoolAllocationMode))
		}
		if props.PublicNetworkAccess != nil {
			publicNetworkAccess = llx.StringData(string(*props.PublicNetworkAccess))
		}
		if props.NodeManagementEndpoint != nil {
			nodeManagementEndpoint = llx.StringData(*props.NodeManagementEndpoint)
		}
		if props.ActiveJobAndJobScheduleQuota != nil {
			activeJobAndJobScheduleQuota = llx.IntData(int64(*props.ActiveJobAndJobScheduleQuota))
		}
		if props.DedicatedCoreQuota != nil {
			dedicatedCoreQuota = llx.IntData(int64(*props.DedicatedCoreQuota))
		}
		if props.DedicatedCoreQuotaPerVMFamilyEnforced != nil {
			dedicatedCoreQuotaPerVmFamilyEnforced = llx.BoolData(*props.DedicatedCoreQuotaPerVMFamilyEnforced)
		}
		if props.LowPriorityCoreQuota != nil {
			lowPriorityCoreQuota = llx.IntData(int64(*props.LowPriorityCoreQuota))
		}
		if props.PoolQuota != nil {
			poolQuota = llx.IntData(int64(*props.PoolQuota))
		}

		if props.AllowedAuthenticationModes != nil {
			values := []any{}
			for _, mode := range props.AllowedAuthenticationModes {
				if mode == nil {
					continue
				}
				values = append(values, string(*mode))
			}
			allowedAuthenticationModes = llx.ArrayData(values, types.String)
		}

		if props.NetworkProfile != nil {
			if dict, err := convert.JsonToDict(props.NetworkProfile); err != nil {
				return nil, err
			} else if dict != nil {
				networkProfile = llx.DictData(dict)
			}
		}

		if props.DedicatedCoreQuotaPerVMFamily != nil {
			items := []any{}
			for _, entry := range props.DedicatedCoreQuotaPerVMFamily {
				if entry == nil {
					continue
				}
				dict, err := convert.JsonToDict(entry)
				if err != nil {
					return nil, err
				}
				items = append(items, dict)
			}
			dedicatedCoreQuotaPerVmFamily = llx.ArrayData(items, types.Dict)
		}

		if props.PrivateEndpointConnections != nil {
			items := []any{}
			for _, entry := range props.PrivateEndpointConnections {
				if entry == nil {
					continue
				}
				dict, err := convert.JsonToDict(entry)
				if err != nil {
					return nil, err
				}
				items = append(items, dict)
			}
			privateEndpointConnections = llx.ArrayData(items, types.Dict)
		}
	}

	return map[string]*llx.RawData{
		"id":                                    llx.StringDataPtr(account.ID),
		"name":                                  llx.StringDataPtr(account.Name),
		"location":                              llx.StringDataPtr(account.Location),
		"tags":                                  llx.MapData(convert.PtrMapStrToInterface(account.Tags), types.String),
		"type":                                  llx.StringDataPtr(account.Type),
		"principalId":                           principalId,
		"properties":                            propertiesData,
		"accountEndpoint":                       accountEndpoint,
		"provisioningState":                     provisioningState,
		"poolAllocationMode":                    poolAllocationMode,
		"publicNetworkAccess":                   publicNetworkAccess,
		"nodeManagementEndpoint":                nodeManagementEndpoint,
		"activeJobAndJobScheduleQuota":          activeJobAndJobScheduleQuota,
		"dedicatedCoreQuota":                    dedicatedCoreQuota,
		"dedicatedCoreQuotaPerVmFamilyEnforced": dedicatedCoreQuotaPerVmFamilyEnforced,
		"dedicatedCoreQuotaPerVmFamily":         dedicatedCoreQuotaPerVmFamily,
		"lowPriorityCoreQuota":                  lowPriorityCoreQuota,
		"poolQuota":                             poolQuota,
		"allowedAuthenticationModes":            allowedAuthenticationModes,
		"networkProfile":                        networkProfile,
		"privateEndpointConnections":            privateEndpointConnections,
	}, nil
}

func batchAccountToMql(runtime *plugin.Runtime, account *armbatch.Account) (*mqlAzureSubscriptionBatchServiceAccount, error) {
	rawData, err := createBatchAccountRawData(account)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, ResourceAzureSubscriptionBatchServiceAccount, rawData)
	if err != nil {
		return nil, err
	}

	sysData, err := convert.JsonToDict(account.SystemData)
	if err != nil {
		return nil, err
	}
	mqlAccount := res.(*mqlAzureSubscriptionBatchServiceAccount)
	mqlAccount.cacheSystemData = sysData

	if account.Identity != nil {
		mqlAccount.cacheUserAssignedIdentityIds = sortedUserAssignedIdentityIDs(account.Identity.UserAssignedIdentities)
	}
	if account.Properties != nil {
		props := account.Properties
		if props.KeyVaultReference != nil && props.KeyVaultReference.ID != nil {
			mqlAccount.cacheKeyVaultId = *props.KeyVaultReference.ID
		}
		if props.AutoStorage != nil && props.AutoStorage.StorageAccountID != nil {
			mqlAccount.cacheAutoStorageAccountId = *props.AutoStorage.StorageAccountID
		}
		if props.Encryption != nil && props.Encryption.KeyVaultProperties != nil && props.Encryption.KeyVaultProperties.KeyIdentifier != nil {
			mqlAccount.cacheEncryptionKeyId = *props.Encryption.KeyVaultProperties.KeyIdentifier
		}
	}

	return mqlAccount, nil
}

type mqlAzureSubscriptionBatchServiceAccountInternal struct {
	cacheSystemData              any
	cacheKeyVaultId              string
	cacheEncryptionKeyId         string
	cacheAutoStorageAccountId    string
	cacheUserAssignedIdentityIds []string
}

func (a *mqlAzureSubscriptionBatchServiceAccount) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

func (a *mqlAzureSubscriptionBatchServiceAccount) keyVault() (*mqlAzureSubscriptionKeyVaultServiceVault, error) {
	if a.cacheKeyVaultId == "" {
		a.KeyVault.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.keyVaultService.vault",
		map[string]*llx.RawData{"id": llx.StringData(a.cacheKeyVaultId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionKeyVaultServiceVault), nil
}

func (a *mqlAzureSubscriptionBatchServiceAccount) encryptionKey() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	if a.cacheEncryptionKeyId == "" {
		a.EncryptionKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, a.cacheEncryptionKeyId)
}

func (a *mqlAzureSubscriptionBatchServiceAccount) autoStorageAccount() (*mqlAzureSubscriptionStorageServiceAccount, error) {
	if a.cacheAutoStorageAccountId == "" {
		a.AutoStorageAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.storageService.account",
		map[string]*llx.RawData{"id": llx.StringData(a.cacheAutoStorageAccountId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionStorageServiceAccount), nil
}

func (a *mqlAzureSubscriptionBatchServiceAccount) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionBatchServiceAccount) pools() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	ctx := context.Background()
	token := conn.Token()

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}

	accountName, err := resourceID.Component("batchAccounts")
	if err != nil {
		return nil, err
	}

	client, err := armbatch.NewPoolClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListByBatchAccountPager(resourceID.ResourceGroup, accountName, &armbatch.PoolClientListByBatchAccountOptions{})
	res := []any{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureNotConfigured(err) {
				log.Warn().Err(err).Msg("could not list azure pools, returning partial results")
				return res, nil
			}
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}

			poolResource, err := batchPoolToMql(a.MqlRuntime, entry)
			if err != nil {
				return nil, err
			}
			res = append(res, poolResource)
		}
	}

	return res, nil
}

func (p *mqlAzureSubscriptionBatchServiceAccountPool) id() (string, error) {
	return p.Id.Data, nil
}

func (a *mqlAzureSubscriptionBatchServiceAccount) diagnosticSettings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	return getDiagnosticSettings(a.Id.Data, a.MqlRuntime, conn)
}

func (a *mqlAzureSubscriptionBatchServiceAccount) diagnosticSettingsCategories() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	return getDiagnosticSettingsCategories(a.Id.Data, a.MqlRuntime, conn)
}

func createBatchPoolRawData(runtime *plugin.Runtime, pool *armbatch.Pool) (map[string]*llx.RawData, error) {
	identityData := llx.NilData
	if pool.Identity != nil {
		if dict, err := convert.JsonToDict(pool.Identity); err != nil {
			return nil, err
		} else if dict != nil {
			identityData = llx.DictData(dict)
		}
	}

	propertiesData := llx.NilData
	var (
		deploymentConfigurationData     = llx.NilData
		virtualMachineConfigurationData = llx.NilData
		vmSizeData                      = llx.NilData
		provisioningStateData           = llx.NilData
		diskCustomerManagedKeyEnabled   = llx.NilData
		diskEncryptionTargets           = llx.NilData
		hostEndpointProtectionMode      = llx.NilData
		proxyAgentEnabled               = llx.NilData
		securityEncryptionType          = llx.NilData
		securityType                    = llx.NilData
		creationTimeData                = llx.NilData
	)

	if pool.Properties != nil {
		if pool.Properties.CreationTime != nil {
			creationTimeData = llx.TimeDataPtr(pool.Properties.CreationTime)
		}
		if dict, err := convert.JsonToDict(pool.Properties); err != nil {
			return nil, err
		} else if dict != nil {
			propertiesData = llx.DictData(dict)
		}

		if pool.Properties.DeploymentConfiguration != nil {
			if dict, err := convert.JsonToDict(pool.Properties.DeploymentConfiguration); err != nil {
				return nil, err
			} else if dict != nil {
				deploymentConfigurationData = llx.DictData(dict)
			}

			if pool.Properties.DeploymentConfiguration.VirtualMachineConfiguration != nil {
				if dict, err := convert.JsonToDict(pool.Properties.DeploymentConfiguration.VirtualMachineConfiguration); err != nil {
					return nil, err
				} else if dict != nil {
					virtualMachineConfigurationData = llx.DictData(dict)
				}
			}
		}

		if pool.Properties.VMSize != nil {
			vmSizeData = llx.StringData(*pool.Properties.VMSize)
		}

		if pool.Properties.ProvisioningState != nil {
			provisioningStateData = llx.StringData(string(*pool.Properties.ProvisioningState))
		}

		// Extract new v4 security fields from deployment configuration
		if pool.Properties.DeploymentConfiguration != nil && pool.Properties.DeploymentConfiguration.VirtualMachineConfiguration != nil {
			vmConfig := pool.Properties.DeploymentConfiguration.VirtualMachineConfiguration

			// Disk encryption configuration
			if vmConfig.DiskEncryptionConfiguration != nil {
				dec := vmConfig.DiskEncryptionConfiguration
				diskCustomerManagedKeyEnabled = llx.BoolData(dec.CustomerManagedKey != nil && dec.CustomerManagedKey.KeyURL != nil && *dec.CustomerManagedKey.KeyURL != "")
				if dec.Targets != nil {
					targets := []any{}
					for _, t := range dec.Targets {
						if t != nil {
							targets = append(targets, string(*t))
						}
					}
					diskEncryptionTargets = llx.ArrayData(targets, types.String)
				} else {
					diskEncryptionTargets = llx.ArrayData([]any{}, types.String)
				}
			} else {
				diskCustomerManagedKeyEnabled = llx.BoolData(false)
				diskEncryptionTargets = llx.ArrayData([]any{}, types.String)
			}

			// Security profile
			if vmConfig.SecurityProfile != nil {
				sp := vmConfig.SecurityProfile
				if sp.ProxyAgentSettings != nil {
					proxyAgentEnabled = llx.BoolDataPtr(sp.ProxyAgentSettings.Enabled)
					// Imds is of type HostEndpointSettings; Mode is the access control policy
					// execution mode ("Audit" or "Enforce") for the IMDS endpoint protection.
					if sp.ProxyAgentSettings.Imds != nil && sp.ProxyAgentSettings.Imds.Mode != nil {
						hostEndpointProtectionMode = llx.StringData(string(*sp.ProxyAgentSettings.Imds.Mode))
					}
				}
				if sp.SecurityType != nil {
					securityType = llx.StringData(string(*sp.SecurityType))
				}
			}

			// securityEncryptionType lives on the managed OS disk's own
			// security profile, not on the VM security profile: SecurityType
			// is confidentialVM/trustedLaunch, while the encryption type is
			// VMGuestStateOnly/DiskWithVMGuestState.
			if osDisk := vmConfig.OSDisk; osDisk != nil && osDisk.ManagedDisk != nil &&
				osDisk.ManagedDisk.SecurityProfile != nil &&
				osDisk.ManagedDisk.SecurityProfile.SecurityEncryptionType != nil {
				securityEncryptionType = llx.StringData(string(*osDisk.ManagedDisk.SecurityProfile.SecurityEncryptionType))
			}
		}
	}

	args := map[string]*llx.RawData{
		"id":                            llx.StringDataPtr(pool.ID),
		"name":                          llx.StringDataPtr(pool.Name),
		"type":                          llx.StringDataPtr(pool.Type),
		"etag":                          llx.StringDataPtr(pool.Etag),
		"identity":                      identityData,
		"properties":                    propertiesData,
		"deploymentConfiguration":       deploymentConfigurationData,
		"virtualMachineConfiguration":   virtualMachineConfigurationData,
		"vmSize":                        vmSizeData,
		"provisioningState":             provisioningStateData,
		"diskCustomerManagedKeyEnabled": diskCustomerManagedKeyEnabled,
		"diskEncryptionTargets":         diskEncryptionTargets,
		"hostEndpointProtectionMode":    hostEndpointProtectionMode,
		"proxyAgentEnabled":             proxyAgentEnabled,
		"securityEncryptionType":        securityEncryptionType,
		"securityType":                  securityType,
		"creationTime":                  creationTimeData,
	}
	// armbatch.PoolIdentity carries only Type and UserAssignedIdentities; a
	// pool has no system-assigned principal or tenant to report, so those
	// members of the shared identity resource stay null rather than reading as
	// empty strings.
	poolIdentity := orZero(pool.Identity)
	if err := setResourceIdentity(runtime, args, sortedUserAssignedIdentityIDs(poolIdentity.UserAssignedIdentities),
		identityType(poolIdentity.Type)); err != nil {
		return nil, err
	}
	return args, nil
}

func batchPoolToMql(runtime *plugin.Runtime, pool *armbatch.Pool) (*mqlAzureSubscriptionBatchServiceAccountPool, error) {
	rawData, err := createBatchPoolRawData(runtime, pool)
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(runtime, ResourceAzureSubscriptionBatchServiceAccountPool, rawData)
	if err != nil {
		return nil, err
	}

	sysData, err := convert.JsonToDict(pool.SystemData)
	if err != nil {
		return nil, err
	}
	mqlPool := resource.(*mqlAzureSubscriptionBatchServiceAccountPool)
	mqlPool.cacheSystemData = sysData

	return mqlPool, nil
}

type mqlAzureSubscriptionBatchServiceAccountPoolInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionBatchServiceAccountPool) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}
