// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// -----------------------------------------------------------------------------
// Public IP prefixes
// -----------------------------------------------------------------------------

type mqlAzureSubscriptionNetworkServicePublicIpPrefixInternal struct {
	cacheCustomIpPrefixId *string
}

func (a *mqlAzureSubscriptionNetworkService) publicIpPrefixes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := network.NewPublicIPPrefixesClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListAllPager(&network.PublicIPPrefixesClientListAllOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, prefix := range page.Value {
			if prefix == nil {
				continue
			}
			mqlPrefix, err := azurePublicIpPrefixToMql(a.MqlRuntime, prefix)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPrefix)
		}
	}
	return res, nil
}

// azurePublicIpPrefixToMql maps a public IP prefix into its MQL resource,
// caching the custom IP prefix ID for the typed reference. Shared by the list
// accessor and the by-ID init.
func azurePublicIpPrefixToMql(runtime *plugin.Runtime, prefix *network.PublicIPPrefix) (*mqlAzureSubscriptionNetworkServicePublicIpPrefix, error) {
	var provisioningState, ipPrefix, ipVersion, resourceGuid string
	var prefixLength int64
	ipTags := []any{}
	var customIpPrefixId *string
	var upgradedToV2 *bool
	if p := prefix.Properties; p != nil {
		upgradedToV2 = p.UpgradedToV2
		if p.ProvisioningState != nil {
			provisioningState = string(*p.ProvisioningState)
		}
		ipPrefix = convert.ToValue(p.IPPrefix)
		resourceGuid = convert.ToValue(p.ResourceGUID)
		if p.PublicIPAddressVersion != nil {
			ipVersion = string(*p.PublicIPAddressVersion)
		}
		if p.PrefixLength != nil {
			prefixLength = int64(*p.PrefixLength)
		}
		tags, err := convert.JsonToDictSlice(p.IPTags)
		if err != nil {
			return nil, err
		}
		ipTags = tags
		if p.CustomIPPrefix != nil {
			customIpPrefixId = p.CustomIPPrefix.ID
		}
	}
	var skuName, skuTier string
	if prefix.SKU != nil {
		if prefix.SKU.Name != nil {
			skuName = string(*prefix.SKU.Name)
		}
		if prefix.SKU.Tier != nil {
			skuTier = string(*prefix.SKU.Tier)
		}
	}
	mqlPrefix, err := CreateResource(runtime, "azure.subscription.networkService.publicIpPrefix",
		map[string]*llx.RawData{
			"id":                llx.StringDataPtr(prefix.ID),
			"name":              llx.StringDataPtr(prefix.Name),
			"location":          llx.StringDataPtr(prefix.Location),
			"tags":              llx.MapData(convert.PtrMapStrToInterface(prefix.Tags), types.String),
			"type":              llx.StringDataPtr(prefix.Type),
			"etag":              llx.StringDataPtr(prefix.Etag),
			"provisioningState": llx.StringData(provisioningState),
			"zones":             llx.ArrayData(strPtrsToAny(prefix.Zones), types.String),
			"prefixLength":      llx.IntData(prefixLength),
			"ipPrefix":          llx.StringData(ipPrefix),
			"ipVersion":         llx.StringData(ipVersion),
			"skuName":           llx.StringData(skuName),
			"skuTier":           llx.StringData(skuTier),
			"resourceGuid":      llx.StringData(resourceGuid),
			"ipTags":            llx.ArrayData(ipTags, types.Dict),
			"upgradedToV2":      llx.BoolDataPtr(upgradedToV2),
		})
	if err != nil {
		return nil, err
	}
	mqlPrefix.(*mqlAzureSubscriptionNetworkServicePublicIpPrefix).cacheCustomIpPrefixId = customIpPrefixId
	return mqlPrefix.(*mqlAzureSubscriptionNetworkServicePublicIpPrefix), nil
}

func (a *mqlAzureSubscriptionNetworkServicePublicIpPrefix) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServicePublicIpPrefix) customIpPrefix() (*mqlAzureSubscriptionNetworkServiceCustomIpPrefix, error) {
	if a.cacheCustomIpPrefixId == nil || *a.cacheCustomIpPrefixId == "" {
		a.CustomIpPrefix.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.customIpPrefix", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cacheCustomIpPrefixId),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionNetworkServiceCustomIpPrefix), nil
}

// -----------------------------------------------------------------------------
// Custom IP prefixes (BYOIP)
// -----------------------------------------------------------------------------

func (a *mqlAzureSubscriptionNetworkService) customIpPrefixes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := network.NewCustomIPPrefixesClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListAllPager(&network.CustomIPPrefixesClientListAllOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, prefix := range page.Value {
			if prefix == nil {
				continue
			}
			mqlPrefix, err := azureCustomIpPrefixToMql(a.MqlRuntime, prefix)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPrefix)
		}
	}
	return res, nil
}

func azureCustomIpPrefixToMql(runtime *plugin.Runtime, prefix *network.CustomIPPrefix) (*mqlAzureSubscriptionNetworkServiceCustomIpPrefix, error) {
	var provisioningState, cidr, asn, commissionedState, prefixType, geo string
	var authorizationMessage, signedMessage, failedReason, resourceGuid string
	var expressRouteAdvertise, noInternetAdvertise bool
	if p := prefix.Properties; p != nil {
		if p.ProvisioningState != nil {
			provisioningState = string(*p.ProvisioningState)
		}
		cidr = convert.ToValue(p.Cidr)
		asn = convert.ToValue(p.Asn)
		if p.CommissionedState != nil {
			commissionedState = string(*p.CommissionedState)
		}
		if p.PrefixType != nil {
			prefixType = string(*p.PrefixType)
		}
		if p.Geo != nil {
			geo = string(*p.Geo)
		}
		authorizationMessage = convert.ToValue(p.AuthorizationMessage)
		signedMessage = convert.ToValue(p.SignedMessage)
		failedReason = convert.ToValue(p.FailedReason)
		resourceGuid = convert.ToValue(p.ResourceGUID)
		expressRouteAdvertise = convert.ToValue(p.ExpressRouteAdvertise)
		noInternetAdvertise = convert.ToValue(p.NoInternetAdvertise)
	}
	mqlPrefix, err := CreateResource(runtime, "azure.subscription.networkService.customIpPrefix",
		map[string]*llx.RawData{
			"id":                    llx.StringDataPtr(prefix.ID),
			"name":                  llx.StringDataPtr(prefix.Name),
			"location":              llx.StringDataPtr(prefix.Location),
			"tags":                  llx.MapData(convert.PtrMapStrToInterface(prefix.Tags), types.String),
			"type":                  llx.StringDataPtr(prefix.Type),
			"etag":                  llx.StringDataPtr(prefix.Etag),
			"provisioningState":     llx.StringData(provisioningState),
			"zones":                 llx.ArrayData(strPtrsToAny(prefix.Zones), types.String),
			"cidr":                  llx.StringData(cidr),
			"asn":                   llx.StringData(asn),
			"commissionedState":     llx.StringData(commissionedState),
			"prefixType":            llx.StringData(prefixType),
			"geo":                   llx.StringData(geo),
			"expressRouteAdvertise": llx.BoolData(expressRouteAdvertise),
			"noInternetAdvertise":   llx.BoolData(noInternetAdvertise),
			"authorizationMessage":  llx.StringData(authorizationMessage),
			"signedMessage":         llx.StringData(signedMessage),
			"failedReason":          llx.StringData(failedReason),
			"resourceGuid":          llx.StringData(resourceGuid),
		})
	if err != nil {
		return nil, err
	}
	return mqlPrefix.(*mqlAzureSubscriptionNetworkServiceCustomIpPrefix), nil
}

func (a *mqlAzureSubscriptionNetworkServiceCustomIpPrefix) id() (string, error) {
	return a.Id.Data, nil
}

func initAzureSubscriptionNetworkServiceCustomIpPrefix(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	name, err := azureId.Component("customIpPrefixes")
	if err != nil {
		return nil, nil, err
	}
	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServiceCustomIpPrefix, id); cached != nil {
		return args, cached, nil
	}

	client, err := network.NewCustomIPPrefixesClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), azureId.ResourceGroup, name, nil)
	if err != nil {
		return nil, nil, err
	}
	mql, err := azureCustomIpPrefixToMql(runtime, &resp.CustomIPPrefix)
	if err != nil {
		return nil, nil, err
	}
	return args, mql, nil
}

// -----------------------------------------------------------------------------
// IP allocations
// -----------------------------------------------------------------------------

type mqlAzureSubscriptionNetworkServiceIpAllocationInternal struct {
	cacheSubnetId         *string
	cacheVirtualNetworkId *string
}

func (a *mqlAzureSubscriptionNetworkService) ipAllocations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := network.NewIPAllocationsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(&network.IPAllocationsClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, alloc := range page.Value {
			if alloc == nil {
				continue
			}
			mqlAlloc, err := azureIpAllocationToMql(a.MqlRuntime, alloc)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAlloc)
		}
	}
	return res, nil
}

// azureIpAllocationToMql maps an IP allocation into its MQL resource, caching
// the subnet and virtual network IDs for the typed references. Shared by the
// list accessor and the by-ID init.
func azureIpAllocationToMql(runtime *plugin.Runtime, alloc *network.IPAllocation) (*mqlAzureSubscriptionNetworkServiceIpAllocation, error) {
	var allocType, prefix, prefixType string
	var prefixLength int64
	allocationTags := map[string]*string{}
	var subnetId, vnetId *string
	if p := alloc.Properties; p != nil {
		if p.Type != nil {
			allocType = string(*p.Type)
		}
		prefix = convert.ToValue(p.Prefix)
		if p.PrefixType != nil {
			prefixType = string(*p.PrefixType)
		}
		if p.PrefixLength != nil {
			prefixLength = int64(*p.PrefixLength)
		}
		allocationTags = p.AllocationTags
		if p.Subnet != nil {
			subnetId = p.Subnet.ID
		}
		if p.VirtualNetwork != nil {
			vnetId = p.VirtualNetwork.ID
		}
	}
	mqlAlloc, err := CreateResource(runtime, "azure.subscription.networkService.ipAllocation",
		map[string]*llx.RawData{
			"id":               llx.StringDataPtr(alloc.ID),
			"name":             llx.StringDataPtr(alloc.Name),
			"location":         llx.StringDataPtr(alloc.Location),
			"tags":             llx.MapData(convert.PtrMapStrToInterface(alloc.Tags), types.String),
			"type":             llx.StringDataPtr(alloc.Type),
			"etag":             llx.StringDataPtr(alloc.Etag),
			"ipAllocationType": llx.StringData(allocType),
			"prefix":           llx.StringData(prefix),
			"prefixLength":     llx.IntData(prefixLength),
			"prefixType":       llx.StringData(prefixType),
			"allocationTags":   llx.MapData(convert.PtrMapStrToInterface(allocationTags), types.String),
		})
	if err != nil {
		return nil, err
	}
	mqlIpAllocation := mqlAlloc.(*mqlAzureSubscriptionNetworkServiceIpAllocation)
	mqlIpAllocation.cacheSubnetId = subnetId
	mqlIpAllocation.cacheVirtualNetworkId = vnetId
	return mqlIpAllocation, nil
}

func (a *mqlAzureSubscriptionNetworkServiceIpAllocation) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceIpAllocation) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	if a.cacheSubnetId == nil || *a.cacheSubnetId == "" {
		a.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.subnet", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cacheSubnetId),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionNetworkServiceSubnet), nil
}

func (a *mqlAzureSubscriptionNetworkServiceIpAllocation) virtualNetwork() (*mqlAzureSubscriptionNetworkServiceVirtualNetwork, error) {
	if a.cacheVirtualNetworkId == nil || *a.cacheVirtualNetworkId == "" {
		a.VirtualNetwork.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.virtualNetwork", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cacheVirtualNetworkId),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionNetworkServiceVirtualNetwork), nil
}

// initAzureSubscriptionNetworkServicePublicIpPrefix resolves a public IP prefix
// by its ARM ID so typed references to it (e.g. from a public IP address)
// populate fully.
func initAzureSubscriptionNetworkServicePublicIpPrefix(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	name, err := azureId.Component("publicIPPrefixes")
	if err != nil {
		return nil, nil, err
	}
	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServicePublicIpPrefix, id); cached != nil {
		return args, cached, nil
	}

	client, err := network.NewPublicIPPrefixesClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), azureId.ResourceGroup, name, nil)
	if err != nil {
		return nil, nil, err
	}
	mql, err := azurePublicIpPrefixToMql(runtime, &resp.PublicIPPrefix)
	if err != nil {
		return nil, nil, err
	}
	return args, mql, nil
}

// initAzureSubscriptionNetworkServiceIpAllocation resolves an IP allocation by
// its ARM ID so typed references to it (e.g. from a subnet) populate fully.
func initAzureSubscriptionNetworkServiceIpAllocation(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	name, err := azureId.Component("ipAllocations")
	if err != nil {
		return nil, nil, err
	}
	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServiceIpAllocation, id); cached != nil {
		return args, cached, nil
	}

	client, err := network.NewIPAllocationsClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), azureId.ResourceGroup, name, nil)
	if err != nil {
		return nil, nil, err
	}
	mql, err := azureIpAllocationToMql(runtime, &resp.IPAllocation)
	if err != nil {
		return nil, nil, err
	}
	return args, mql, nil
}
