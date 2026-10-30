// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appconfiguration/armappconfiguration/v3"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func initAzureSubscriptionAppConfigurationService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionAppConfigurationService) id() (string, error) {
	return "azure.subscription.appConfigurationService/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionAppConfigurationServiceConfigurationStore) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAppConfigurationService) configurationStores() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	ctx := context.Background()
	client, err := armappconfiguration.NewConfigurationStoresClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list app configuration stores due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, store := range page.Value {
			if store == nil {
				continue
			}
			mqlStore, err := configurationStoreToMql(a.MqlRuntime, store)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlStore)
		}
	}
	return res, nil
}

func configurationStoreToMql(runtime *plugin.Runtime, store *armappconfiguration.ConfigurationStore) (*mqlAzureSubscriptionAppConfigurationServiceConfigurationStore, error) {
	sku, err := convert.JsonToDict(store.SKU)
	storeSku := orZero(store.SKU)
	if err != nil {
		return nil, err
	}
	identity, err := convert.JsonToDict(store.Identity)
	if err != nil {
		return nil, err
	}

	var publicNetworkAccess, cmkKeyIdentifier, cmkIdentityClientId string
	var endpoint, provisioningState, createMode string
	var dataPlaneProxyAuthenticationMode, dataPlaneProxyPrivateLinkDelegation *string
	var disableLocalAuth, enablePurgeProtection bool
	var softDeleteRetentionInDays, defaultKeyValueRevisionRetentionPeriodInSeconds int64
	var creationTime *time.Time

	if p := store.Properties; p != nil {
		creationTime = p.CreationDate
		if p.PublicNetworkAccess != nil {
			publicNetworkAccess = string(*p.PublicNetworkAccess)
		}
		if p.DisableLocalAuth != nil {
			disableLocalAuth = *p.DisableLocalAuth
		}
		if p.EnablePurgeProtection != nil {
			enablePurgeProtection = *p.EnablePurgeProtection
		}
		if p.SoftDeleteRetentionInDays != nil {
			softDeleteRetentionInDays = int64(*p.SoftDeleteRetentionInDays)
		}
		if p.DefaultKeyValueRevisionRetentionPeriodInSeconds != nil {
			defaultKeyValueRevisionRetentionPeriodInSeconds = *p.DefaultKeyValueRevisionRetentionPeriodInSeconds
		}
		if enc := p.Encryption; enc != nil && enc.KeyVaultProperties != nil {
			if enc.KeyVaultProperties.KeyIdentifier != nil {
				cmkKeyIdentifier = *enc.KeyVaultProperties.KeyIdentifier
			}
			if enc.KeyVaultProperties.IdentityClientID != nil {
				cmkIdentityClientId = *enc.KeyVaultProperties.IdentityClientID
			}
		}
		if p.Endpoint != nil {
			endpoint = *p.Endpoint
		}
		if p.ProvisioningState != nil {
			provisioningState = string(*p.ProvisioningState)
		}
		if p.CreateMode != nil {
			createMode = string(*p.CreateMode)
		}
		if dpp := p.DataPlaneProxy; dpp != nil {
			dataPlaneProxyAuthenticationMode = stringEnumPtr(dpp.AuthenticationMode)
			dataPlaneProxyPrivateLinkDelegation = stringEnumPtr(dpp.PrivateLinkDelegation)
		}
	}

	args := map[string]*llx.RawData{
		"id":                                  llx.StringDataPtr(store.ID),
		"name":                                llx.StringDataPtr(store.Name),
		"location":                            llx.StringDataPtr(store.Location),
		"tags":                                llx.MapData(convert.PtrMapStrToInterface(store.Tags), types.String),
		"sku":                                 llx.DictData(sku),
		"identity":                            llx.DictData(identity),
		"publicNetworkAccess":                 llx.StringData(publicNetworkAccess),
		"disableLocalAuth":                    llx.BoolData(disableLocalAuth),
		"cmkKeyIdentifier":                    llx.StringData(cmkKeyIdentifier),
		"cmkIdentityClientId":                 llx.StringData(cmkIdentityClientId),
		"softDeleteRetentionInDays":           llx.IntData(softDeleteRetentionInDays),
		"enablePurgeProtection":               llx.BoolData(enablePurgeProtection),
		"dataPlaneProxyAuthenticationMode":    llx.StringDataPtr(dataPlaneProxyAuthenticationMode),
		"dataPlaneProxyPrivateLinkDelegation": llx.StringDataPtr(dataPlaneProxyPrivateLinkDelegation),
		"endpoint":                            llx.StringData(endpoint),
		"provisioningState":                   llx.StringData(provisioningState),
		"createMode":                          llx.StringData(createMode),
		"defaultKeyValueRevisionRetentionPeriodInSeconds": llx.IntData(defaultKeyValueRevisionRetentionPeriodInSeconds),
		"creationTime": llx.TimeDataPtr(creationTime),
	}
	if err := setSkuData(runtime, args, skuName(storeSku.Name)); err != nil {
		return nil, err
	}
	storeIdentity := orZero(store.Identity)
	if err := setResourceIdentity(runtime, args, sortedUserAssignedIdentityIDs(storeIdentity.UserAssignedIdentities),
		identityType(storeIdentity.Type), identityPrincipalId(storeIdentity.PrincipalID), identityTenantId(storeIdentity.TenantID)); err != nil {
		return nil, err
	}
	res, err := CreateResource(runtime, "azure.subscription.appConfigurationService.configurationStore", args)
	if err != nil {
		return nil, err
	}
	mqlStore := res.(*mqlAzureSubscriptionAppConfigurationServiceConfigurationStore)
	sysData, err := convert.JsonToDict(store.SystemData)
	if err != nil {
		return nil, err
	}
	mqlStore.cacheSystemData = sysData
	if store.Properties != nil {
		mqlStore.cachePrivateEndpointConnections = store.Properties.PrivateEndpointConnections
	}
	return mqlStore, nil
}

type mqlAzureSubscriptionAppConfigurationServiceConfigurationStoreInternal struct {
	cacheSystemData                 any
	cachePrivateEndpointConnections []*armappconfiguration.PrivateEndpointConnectionReference
}

func (a *mqlAzureSubscriptionAppConfigurationServiceConfigurationStore) privateEndpointConnections() ([]any, error) {
	return azurePrivateEndpointConnectionsToMql(a.MqlRuntime, a.cachePrivateEndpointConnections)
}
