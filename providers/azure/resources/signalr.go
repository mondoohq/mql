// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/signalr/armsignalr"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/webpubsub/armwebpubsub"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func initAzureSubscriptionSignalRService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionSignalRService) id() (string, error) {
	return "azure.subscription.signalRService/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionSignalRServiceSignalR) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionSignalRService) instances() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	ctx := context.Background()
	client, err := armsignalr.NewClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListBySubscriptionPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list SignalR instances due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, sr := range page.Value {
			if sr == nil {
				continue
			}
			mqlSr, err := signalRToMql(a.MqlRuntime, sr)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSr)
		}
	}
	return res, nil
}

func signalRToMql(runtime *plugin.Runtime, sr *armsignalr.ResourceInfo) (*mqlAzureSubscriptionSignalRServiceSignalR, error) {
	sku, err := convert.JsonToDict(sr.SKU)
	if err != nil {
		return nil, err
	}
	identity, err := convert.JsonToDict(sr.Identity)
	if err != nil {
		return nil, err
	}

	var hostName, externalIP, version, publicNetworkAccess, networkAclsDefaultAction, provisioningState string
	var disableLocalAuth, disableAadAuth, clientCertEnabled bool
	if p := sr.Properties; p != nil {
		hostName = convert.ToValue(p.HostName)
		externalIP = convert.ToValue(p.ExternalIP)
		version = convert.ToValue(p.Version)
		publicNetworkAccess = convert.ToValue(p.PublicNetworkAccess)
		disableLocalAuth = convert.ToValue(p.DisableLocalAuth)
		disableAadAuth = convert.ToValue(p.DisableAADAuth)
		provisioningState = string(convert.ToValue(p.ProvisioningState))
		if p.TLS != nil {
			clientCertEnabled = convert.ToValue(p.TLS.ClientCertEnabled)
		}
		if p.NetworkACLs != nil {
			networkAclsDefaultAction = string(convert.ToValue(p.NetworkACLs.DefaultAction))
		}
	}

	args := map[string]*llx.RawData{
		"id":                       llx.StringDataPtr(sr.ID),
		"name":                     llx.StringDataPtr(sr.Name),
		"location":                 llx.StringDataPtr(sr.Location),
		"tags":                     llx.MapData(convert.PtrMapStrToInterface(sr.Tags), types.String),
		"kind":                     llx.StringData(string(convert.ToValue(sr.Kind))),
		"sku":                      llx.DictData(sku),
		"identity":                 llx.DictData(identity),
		"hostName":                 llx.StringData(hostName),
		"externalIp":               llx.StringData(externalIP),
		"version":                  llx.StringData(version),
		"publicNetworkAccess":      llx.StringData(publicNetworkAccess),
		"disableLocalAuth":         llx.BoolData(disableLocalAuth),
		"disableAadAuth":           llx.BoolData(disableAadAuth),
		"clientCertEnabled":        llx.BoolData(clientCertEnabled),
		"networkAclsDefaultAction": llx.StringData(networkAclsDefaultAction),
		"provisioningState":        llx.StringData(provisioningState),
	}
	srSku := orZero(sr.SKU)
	if err := setSkuData(runtime, args, skuName(srSku.Name), skuTier(srSku.Tier), skuCapacity(srSku.Capacity)); err != nil {
		return nil, err
	}

	srIdentity := orZero(sr.Identity)
	if err := setResourceIdentity(runtime, args, sortedUserAssignedIdentityIDs(srIdentity.UserAssignedIdentities),
		identityType(srIdentity.Type), identityPrincipalId(srIdentity.PrincipalID), identityTenantId(srIdentity.TenantID)); err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "azure.subscription.signalRService.signalR", args)
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(sr.SystemData)
	if err != nil {
		return nil, err
	}
	mqlSr := res.(*mqlAzureSubscriptionSignalRServiceSignalR)
	mqlSr.cacheSystemData = sysData
	if sr.Properties != nil {
		mqlSr.cachePrivateEndpointConnections = sr.Properties.PrivateEndpointConnections
	}
	return mqlSr, nil
}

type mqlAzureSubscriptionSignalRServiceSignalRInternal struct {
	cacheSystemData                 any
	cachePrivateEndpointConnections []*armsignalr.PrivateEndpointConnection
}

func (a *mqlAzureSubscriptionSignalRServiceSignalR) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionSignalRServiceSignalR) privateEndpointConnections() ([]any, error) {
	return azurePrivateEndpointConnectionsToMql(a.MqlRuntime, a.cachePrivateEndpointConnections)
}

func initAzureSubscriptionWebPubSubService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionWebPubSubService) id() (string, error) {
	return "azure.subscription.webPubSubService/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionWebPubSubServiceWebPubSub) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionWebPubSubService) instances() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	ctx := context.Background()
	client, err := armwebpubsub.NewClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListBySubscriptionPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list Web PubSub instances due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, wps := range page.Value {
			if wps == nil {
				continue
			}
			mqlWps, err := webPubSubToMql(a.MqlRuntime, wps)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlWps)
		}
	}
	return res, nil
}

func webPubSubToMql(runtime *plugin.Runtime, wps *armwebpubsub.ResourceInfo) (*mqlAzureSubscriptionWebPubSubServiceWebPubSub, error) {
	sku, err := convert.JsonToDict(wps.SKU)
	if err != nil {
		return nil, err
	}
	identity, err := convert.JsonToDict(wps.Identity)
	if err != nil {
		return nil, err
	}

	var hostName, externalIP, version, publicNetworkAccess, networkAclsDefaultAction, provisioningState string
	var disableLocalAuth, disableAadAuth, clientCertEnabled bool
	if p := wps.Properties; p != nil {
		hostName = convert.ToValue(p.HostName)
		externalIP = convert.ToValue(p.ExternalIP)
		version = convert.ToValue(p.Version)
		publicNetworkAccess = convert.ToValue(p.PublicNetworkAccess)
		disableLocalAuth = convert.ToValue(p.DisableLocalAuth)
		disableAadAuth = convert.ToValue(p.DisableAADAuth)
		provisioningState = string(convert.ToValue(p.ProvisioningState))
		if p.TLS != nil {
			clientCertEnabled = convert.ToValue(p.TLS.ClientCertEnabled)
		}
		if p.NetworkACLs != nil {
			networkAclsDefaultAction = string(convert.ToValue(p.NetworkACLs.DefaultAction))
		}
	}

	args := map[string]*llx.RawData{
		"id":                       llx.StringDataPtr(wps.ID),
		"name":                     llx.StringDataPtr(wps.Name),
		"location":                 llx.StringDataPtr(wps.Location),
		"tags":                     llx.MapData(convert.PtrMapStrToInterface(wps.Tags), types.String),
		"kind":                     llx.StringData(string(convert.ToValue(wps.Kind))),
		"sku":                      llx.DictData(sku),
		"identity":                 llx.DictData(identity),
		"hostName":                 llx.StringData(hostName),
		"externalIp":               llx.StringData(externalIP),
		"version":                  llx.StringData(version),
		"publicNetworkAccess":      llx.StringData(publicNetworkAccess),
		"disableLocalAuth":         llx.BoolData(disableLocalAuth),
		"disableAadAuth":           llx.BoolData(disableAadAuth),
		"clientCertEnabled":        llx.BoolData(clientCertEnabled),
		"networkAclsDefaultAction": llx.StringData(networkAclsDefaultAction),
		"provisioningState":        llx.StringData(provisioningState),
	}
	wpsSku := orZero(wps.SKU)
	if err := setSkuData(runtime, args, skuName(wpsSku.Name), skuTier(wpsSku.Tier), skuCapacity(wpsSku.Capacity)); err != nil {
		return nil, err
	}

	wpsIdentity := orZero(wps.Identity)
	if err := setResourceIdentity(runtime, args, sortedUserAssignedIdentityIDs(wpsIdentity.UserAssignedIdentities),
		identityType(wpsIdentity.Type), identityPrincipalId(wpsIdentity.PrincipalID), identityTenantId(wpsIdentity.TenantID)); err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "azure.subscription.webPubSubService.webPubSub", args)
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(wps.SystemData)
	if err != nil {
		return nil, err
	}
	mqlWps := res.(*mqlAzureSubscriptionWebPubSubServiceWebPubSub)
	mqlWps.cacheSystemData = sysData
	if wps.Properties != nil {
		mqlWps.cachePrivateEndpointConnections = wps.Properties.PrivateEndpointConnections
	}
	return mqlWps, nil
}

type mqlAzureSubscriptionWebPubSubServiceWebPubSubInternal struct {
	cacheSystemData                 any
	cachePrivateEndpointConnections []*armwebpubsub.PrivateEndpointConnection
}

func (a *mqlAzureSubscriptionWebPubSubServiceWebPubSub) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionWebPubSubServiceWebPubSub) privateEndpointConnections() ([]any, error) {
	return azurePrivateEndpointConnectionsToMql(a.MqlRuntime, a.cachePrivateEndpointConnections)
}
