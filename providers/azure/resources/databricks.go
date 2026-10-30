// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/databricks/armdatabricks/v2"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func initAzureSubscriptionDatabricksService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionDatabricksService) id() (string, error) {
	return "azure.subscription.databricksService/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionDatabricksServiceWorkspace) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionDatabricksService) workspaces() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided. it is not an Azure connection")
	}

	ctx := context.Background()
	client, err := armdatabricks.NewWorkspacesClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListBySubscriptionPager(&armdatabricks.WorkspacesClientListBySubscriptionOptions{})
	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, entry := range page.Value {
			if entry == nil {
				continue
			}

			resource, err := databricksWorkspaceToMql(a.MqlRuntime, entry)
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}
	}

	return keepTagMatches(a.MqlRuntime, res), nil
}

func databricksWorkspaceToMql(runtime *plugin.Runtime, workspace *armdatabricks.Workspace) (*mqlAzureSubscriptionDatabricksServiceWorkspace, error) {
	propertiesData := llx.NilData
	if workspace.Properties != nil {
		if dict, err := convert.JsonToDict(workspace.Properties); err != nil {
			return nil, err
		} else if dict != nil {
			propertiesData = llx.DictData(dict)
		}
	}

	skuData := llx.NilData
	if workspace.SKU != nil {
		if dict, err := convert.JsonToDict(workspace.SKU); err != nil {
			return nil, err
		} else if dict != nil {
			skuData = llx.DictData(dict)
		}
	}

	var publicNetworkAccess, requiredNsgRules, diskEncryptionSetId, managedResourceGroupId, provisioningState, workspaceId string
	var enableNoPublicIp, requireInfraEnc bool
	var isUnityCatalogEnabled *bool
	var computeMode, workspaceUrl, accessConnectorId *string
	var defaultCatalogInitialType, defaultCatalogInitialName *string
	var createdBy, updatedBy any
	var customVnetId string
	var defaultStorageFirewall, complianceSecurityProfile, enhancedSecurityMonitoring, automaticClusterUpdate string
	complianceStandards := []any{}
	var managedDiskKeySource, managedDiskKeyVaultUri, managedDiskKeyName, managedDiskKeyVersion string
	var managedServicesKeySource, managedServicesKeyVaultUri, managedServicesKeyName, managedServicesKeyVersion string
	var creationTime *time.Time

	if props := workspace.Properties; props != nil {
		creationTime = props.CreatedDateTime
		if props.PublicNetworkAccess != nil {
			publicNetworkAccess = string(*props.PublicNetworkAccess)
		}
		if props.RequiredNsgRules != nil {
			requiredNsgRules = string(*props.RequiredNsgRules)
		}
		if props.DiskEncryptionSetID != nil {
			diskEncryptionSetId = *props.DiskEncryptionSetID
		}
		if props.ManagedResourceGroupID != nil {
			managedResourceGroupId = *props.ManagedResourceGroupID
		}
		if props.ProvisioningState != nil {
			provisioningState = string(*props.ProvisioningState)
		}
		if props.WorkspaceID != nil {
			workspaceId = *props.WorkspaceID
		}
		if props.DefaultStorageFirewall != nil {
			defaultStorageFirewall = string(*props.DefaultStorageFirewall)
		}

		if esc := props.EnhancedSecurityCompliance; esc != nil {
			if csp := esc.ComplianceSecurityProfile; csp != nil {
				if csp.Value != nil {
					complianceSecurityProfile = string(*csp.Value)
				}
				for _, std := range csp.ComplianceStandards {
					if std != nil {
						complianceStandards = append(complianceStandards, *std)
					}
				}
			}
			if esm := esc.EnhancedSecurityMonitoring; esm != nil && esm.Value != nil {
				enhancedSecurityMonitoring = string(*esm.Value)
			}
			if acu := esc.AutomaticClusterUpdate; acu != nil && acu.Value != nil {
				automaticClusterUpdate = string(*acu.Value)
			}
		}

		if p := props.Parameters; p != nil {
			if p.EnableNoPublicIP != nil && p.EnableNoPublicIP.Value != nil {
				enableNoPublicIp = *p.EnableNoPublicIP.Value
			}
			if p.RequireInfrastructureEncryption != nil && p.RequireInfrastructureEncryption.Value != nil {
				requireInfraEnc = *p.RequireInfrastructureEncryption.Value
			}
			if p.CustomVirtualNetworkID != nil && p.CustomVirtualNetworkID.Value != nil {
				customVnetId = *p.CustomVirtualNetworkID.Value
			}
			if p.Encryption != nil && p.Encryption.Value != nil {
				if p.Encryption.Value.KeySource != nil {
					managedDiskKeySource = string(*p.Encryption.Value.KeySource)
				}
				if p.Encryption.Value.KeyVaultURI != nil {
					managedDiskKeyVaultUri = *p.Encryption.Value.KeyVaultURI
				}
				if p.Encryption.Value.KeyName != nil {
					managedDiskKeyName = *p.Encryption.Value.KeyName
				}
				if p.Encryption.Value.KeyVersion != nil {
					managedDiskKeyVersion = *p.Encryption.Value.KeyVersion
				}
			}
		}

		if enc := props.Encryption; enc != nil && enc.Entities != nil {
			if md := enc.Entities.ManagedDisk; md != nil {
				// KeySource may be "Default" (Microsoft-managed) without KeyVaultProperties,
				// or "Microsoft.Keyvault" with KV details. Read it independently.
				if md.KeySource != nil {
					managedDiskKeySource = string(*md.KeySource)
				}
				if md.KeyVaultProperties != nil {
					if md.KeyVaultProperties.KeyVaultURI != nil {
						managedDiskKeyVaultUri = *md.KeyVaultProperties.KeyVaultURI
					}
					if md.KeyVaultProperties.KeyName != nil {
						managedDiskKeyName = *md.KeyVaultProperties.KeyName
					}
					if md.KeyVaultProperties.KeyVersion != nil {
						managedDiskKeyVersion = *md.KeyVaultProperties.KeyVersion
					}
				}
			}
			if ms := enc.Entities.ManagedServices; ms != nil {
				if ms.KeySource != nil {
					managedServicesKeySource = string(*ms.KeySource)
				}
				if ms.KeyVaultProperties != nil {
					if ms.KeyVaultProperties.KeyVaultURI != nil {
						managedServicesKeyVaultUri = *ms.KeyVaultProperties.KeyVaultURI
					}
					if ms.KeyVaultProperties.KeyName != nil {
						managedServicesKeyName = *ms.KeyVaultProperties.KeyName
					}
					if ms.KeyVaultProperties.KeyVersion != nil {
						managedServicesKeyVersion = *ms.KeyVaultProperties.KeyVersion
					}
				}
			}
		}

		isUnityCatalogEnabled = props.IsUcEnabled
		computeMode = stringEnumPtr(props.ComputeMode)
		workspaceUrl = props.WorkspaceURL
		if ac := props.AccessConnector; ac != nil {
			accessConnectorId = ac.ID
		}
		if dc := props.DefaultCatalog; dc != nil {
			defaultCatalogInitialType = stringEnumPtr(dc.InitialType)
			defaultCatalogInitialName = dc.InitialName
		}
		var convErr error
		if createdBy, convErr = convert.JsonToDict(props.CreatedBy); convErr != nil {
			return nil, convErr
		}
		if updatedBy, convErr = convert.JsonToDict(props.UpdatedBy); convErr != nil {
			return nil, convErr
		}
	}

	args := map[string]*llx.RawData{
		"id":                              llx.StringDataPtr(workspace.ID),
		"name":                            llx.StringDataPtr(workspace.Name),
		"location":                        llx.StringDataPtr(workspace.Location),
		"tags":                            llx.MapData(convert.PtrMapStrToInterface(workspace.Tags), types.String),
		"type":                            llx.StringDataPtr(workspace.Type),
		"properties":                      propertiesData,
		"sku":                             skuData,
		"publicNetworkAccess":             llx.StringData(publicNetworkAccess),
		"enableNoPublicIp":                llx.BoolData(enableNoPublicIp),
		"requireInfrastructureEncryption": llx.BoolData(requireInfraEnc),
		"customVirtualNetworkId":          llx.StringData(customVnetId),
		"requiredNsgRules":                llx.StringData(requiredNsgRules),
		"defaultStorageFirewall":          llx.StringData(defaultStorageFirewall),
		"complianceSecurityProfile":       llx.StringData(complianceSecurityProfile),
		"complianceStandards":             llx.ArrayData(complianceStandards, types.String),
		"enhancedSecurityMonitoring":      llx.StringData(enhancedSecurityMonitoring),
		"automaticClusterUpdate":          llx.StringData(automaticClusterUpdate),
		"isUnityCatalogEnabled":           llx.BoolDataPtr(isUnityCatalogEnabled),
		"computeMode":                     llx.StringDataPtr(computeMode),
		"workspaceUrl":                    llx.StringDataPtr(workspaceUrl),
		"accessConnectorId":               llx.StringDataPtr(accessConnectorId),
		"defaultCatalogInitialType":       llx.StringDataPtr(defaultCatalogInitialType),
		"defaultCatalogInitialName":       llx.StringDataPtr(defaultCatalogInitialName),
		"createdBy":                       llx.DictData(createdBy),
		"updatedBy":                       llx.DictData(updatedBy),
		"diskEncryptionSetId":             llx.StringData(diskEncryptionSetId),
		"managedResourceGroupId":          llx.StringData(managedResourceGroupId),
		"provisioningState":               llx.StringData(provisioningState),
		"workspaceId":                     llx.StringData(workspaceId),
		"managedDiskKeySource":            llx.StringData(managedDiskKeySource),
		"managedDiskKeyVaultUri":          llx.StringData(managedDiskKeyVaultUri),
		"managedDiskKeyName":              llx.StringData(managedDiskKeyName),
		"managedDiskKeyVersion":           llx.StringData(managedDiskKeyVersion),
		"managedServicesKeySource":        llx.StringData(managedServicesKeySource),
		"managedServicesKeyVaultUri":      llx.StringData(managedServicesKeyVaultUri),
		"managedServicesKeyName":          llx.StringData(managedServicesKeyName),
		"managedServicesKeyVersion":       llx.StringData(managedServicesKeyVersion),
		"creationTime":                    llx.TimeDataPtr(creationTime),
	}
	workspaceSku := orZero(workspace.SKU)
	if err := setSkuData(runtime, args, skuName(workspaceSku.Name), skuTier(workspaceSku.Tier)); err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, ResourceAzureSubscriptionDatabricksServiceWorkspace, args)
	if err != nil {
		return nil, err
	}

	mqlWorkspace := res.(*mqlAzureSubscriptionDatabricksServiceWorkspace)
	sysData, err := convert.JsonToDict(workspace.SystemData)
	if err != nil {
		return nil, err
	}
	mqlWorkspace.cacheSystemData = sysData
	if workspace.Properties != nil {
		mqlWorkspace.cachePrivateEndpointConnections = workspace.Properties.PrivateEndpointConnections
	}

	return mqlWorkspace, nil
}

type mqlAzureSubscriptionDatabricksServiceWorkspaceInternal struct {
	cacheSystemData                 any
	cachePrivateEndpointConnections []*armdatabricks.PrivateEndpointConnection
}

// privateEndpointConnections reports the connections created against the
// workspace's private link resources.
//
// The list arrives with the workspace, so this reads what was already fetched
// rather than issuing a request of its own. The values go through the shared
// converter every other azure resource uses, which normalizes the SDK type
// through a dict, so the workspace's connections are the same resource shape a
// storage account's or a key vault's are and a fleet-wide query over
// privateEndpointConnections stays comparable.
func (a *mqlAzureSubscriptionDatabricksServiceWorkspace) privateEndpointConnections() ([]any, error) {
	return azurePrivateEndpointConnectionsToMql(a.MqlRuntime, a.cachePrivateEndpointConnections)
}

func (a *mqlAzureSubscriptionDatabricksServiceWorkspace) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}
