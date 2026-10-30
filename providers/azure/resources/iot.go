// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/iothub/armiothub"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionIotServiceIotHubInternal struct {
	cacheSystemData                 any
	cacheUserAssignedIdentityIds    []string
	cachePrivateEndpointConnections []*armiothub.PrivateEndpointConnection
}

func (a *mqlAzureSubscriptionIotService) id() (string, error) {
	return "azure.subscription.iot/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionIotServiceIotHub) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

func (a *mqlAzureSubscriptionIotServiceIotHub) privateEndpointConnections() ([]any, error) {
	return azurePrivateEndpointConnectionsToMql(a.MqlRuntime, a.cachePrivateEndpointConnections)
}

func (a *mqlAzureSubscriptionIotServiceIotHub) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionIotServiceIotHub) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionIotServiceIotHub) diagnosticSettings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	return getDiagnosticSettings(a.Id.Data, a.MqlRuntime, conn)
}

func (a *mqlAzureSubscriptionIotServiceIotHub) diagnosticSettingsCategories() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	return getDiagnosticSettingsCategories(a.Id.Data, a.MqlRuntime, conn)
}

func initAzureSubscriptionIotService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, fmt.Errorf("invalid connection provided, it is not an Azure connection")
	}
	args["subscriptionId"] = llx.StringData(conn.SubId())

	return args, nil, nil
}

// initAzureSubscriptionIotServiceIotHub resolves a single IoT hub. When called
// without arguments it falls back to the discovered asset's platform id (see
// getAssetIdentifier), so an azure-iot-iothub asset resolves to its backing
// hub instead of an empty husk.
func initAzureSubscriptionIotServiceIotHub(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil && ids.id != "" {
			args["id"] = llx.StringData(ids.id)
		}
	}

	if args["id"] == nil {
		return nil, nil, fmt.Errorf("id required to fetch azure iot hub")
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, fmt.Errorf("invalid connection provided, it is not an Azure connection")
	}

	res, err := NewResource(runtime, "azure.subscription.iotService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, nil, err
	}
	iotSvc := res.(*mqlAzureSubscriptionIotService)
	hubs := iotSvc.GetIotHubs()
	if hubs.Error != nil {
		return nil, nil, hubs.Error
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	for _, entry := range hubs.Data {
		hub := entry.(*mqlAzureSubscriptionIotServiceIotHub)
		if hub.Id.Data == id {
			return args, hub, nil
		}
	}

	if filtered := tagFilteredOut(runtime, ResourceAzureSubscriptionIotServiceIotHub, id); filtered != nil {
		return args, filtered, nil
	}

	return nil, nil, fmt.Errorf("azure iot hub does not exist")
}

// iotHubs returns typed IoT hub resources with security-relevant fields populated.
func (a *mqlAzureSubscriptionIotService) iotHubs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subscriptionID := a.SubscriptionId.Data

	clientFactory, err := armiothub.NewClientFactory(subscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	client := clientFactory.NewResourceClient()
	pager := client.NewListBySubscriptionPager(nil)

	var res []any
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, hub := range page.Value {
			if hub == nil {
				continue
			}

			sku, err := convert.JsonToDict(hub.SKU)
			if err != nil {
				return nil, err
			}

			var provisioningState, state, hostName, minTlsVersion, publicNetworkAccess string
			var disableLocalAuth, disableDeviceSAS, disableModuleSAS, restrictOutbound, enableDataResidency *bool
			var allowedFqdns []any
			var nrs any
			if props := hub.Properties; props != nil {
				if props.ProvisioningState != nil {
					provisioningState = *props.ProvisioningState
				}
				if props.State != nil {
					state = *props.State
				}
				if props.HostName != nil {
					hostName = *props.HostName
				}
				if props.MinTLSVersion != nil {
					minTlsVersion = *props.MinTLSVersion
				}
				if props.PublicNetworkAccess != nil {
					publicNetworkAccess = string(*props.PublicNetworkAccess)
				}
				disableLocalAuth = props.DisableLocalAuth
				disableDeviceSAS = props.DisableDeviceSAS
				disableModuleSAS = props.DisableModuleSAS
				restrictOutbound = props.RestrictOutboundNetworkAccess
				enableDataResidency = props.EnableDataResidency
				for _, fqdn := range props.AllowedFqdnList {
					if fqdn != nil {
						allowedFqdns = append(allowedFqdns, *fqdn)
					}
				}
				if props.NetworkRuleSets != nil {
					if d, err := convert.JsonToDict(props.NetworkRuleSets); err == nil {
						nrs = d
					}
				}
			}

			var identityType, identityPrincipalId, identityTenantId *string
			var userAssignedIdentityIds []string
			if hub.Identity != nil {
				if hub.Identity.Type != nil {
					s := string(*hub.Identity.Type)
					identityType = &s
				}
				identityPrincipalId = hub.Identity.PrincipalID
				identityTenantId = hub.Identity.TenantID
				userAssignedIdentityIds = sortedUserAssignedIdentityIDs(hub.Identity.UserAssignedIdentities)
			}

			args := map[string]*llx.RawData{
				"id":                            llx.StringDataPtr(hub.ID),
				"name":                          llx.StringDataPtr(hub.Name),
				"type":                          llx.StringDataPtr(hub.Type),
				"location":                      llx.StringDataPtr(hub.Location),
				"tags":                          llx.MapData(convert.PtrMapStrToInterface(hub.Tags), types.String),
				"sku":                           llx.DictData(sku),
				"provisioningState":             llx.StringData(provisioningState),
				"state":                         llx.StringData(state),
				"hostName":                      llx.StringData(hostName),
				"disableLocalAuth":              llx.BoolDataPtr(disableLocalAuth),
				"disableDeviceSAS":              llx.BoolDataPtr(disableDeviceSAS),
				"disableModuleSAS":              llx.BoolDataPtr(disableModuleSAS),
				"minTlsVersion":                 llx.StringData(minTlsVersion),
				"publicNetworkAccess":           llx.StringData(publicNetworkAccess),
				"restrictOutboundNetworkAccess": llx.BoolDataPtr(restrictOutbound),
				"allowedFqdnList":               llx.ArrayData(allowedFqdns, types.String),
				"enableDataResidency":           llx.BoolDataPtr(enableDataResidency),
				"networkRuleSet":                llx.DictData(nrs),
				"identityType":                  llx.StringDataPtr(identityType),
				"principalId":                   llx.StringDataPtr(identityPrincipalId),
				"tenantId":                      llx.StringDataPtr(identityTenantId),
			}
			hubSku := orZero(hub.SKU)
			if err := setSkuData(a.MqlRuntime, args, skuName(hubSku.Name), skuTier(hubSku.Tier), skuCapacity(hubSku.Capacity)); err != nil {
				return nil, err
			}

			mqlHub, err := CreateResource(a.MqlRuntime, "azure.subscription.iotService.iotHub", args)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(hub.SystemData)
			if err != nil {
				return nil, err
			}
			mqlHubRes := mqlHub.(*mqlAzureSubscriptionIotServiceIotHub)
			mqlHubRes.cacheSystemData = sysData
			mqlHubRes.cacheUserAssignedIdentityIds = userAssignedIdentityIds
			if hub.Properties != nil {
				mqlHubRes.cachePrivateEndpointConnections = hub.Properties.PrivateEndpointConnections
			}
			res = append(res, mqlHub)
		}
	}
	return keepTagMatches(a.MqlRuntime, res), nil
}
