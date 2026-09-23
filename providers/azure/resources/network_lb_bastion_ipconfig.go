// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// -----------------------------------------------------------------------------
// Load balancer frontend IP configuration typed references
// -----------------------------------------------------------------------------

type mqlAzureSubscriptionNetworkServiceFrontendIpConfigInternal struct {
	cachePublicIpAddressID *string
	cacheSubnetID          *string
}

func (a *mqlAzureSubscriptionNetworkServiceFrontendIpConfig) publicIpAddress() (*mqlAzureSubscriptionNetworkServiceIpAddress, error) {
	if a.cachePublicIpAddressID == nil || *a.cachePublicIpAddressID == "" {
		a.PublicIpAddress.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.ipAddress", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cachePublicIpAddressID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionNetworkServiceIpAddress), nil
}

func (a *mqlAzureSubscriptionNetworkServiceFrontendIpConfig) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	if a.cacheSubnetID == nil || *a.cacheSubnetID == "" {
		a.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.subnet", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cacheSubnetID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionNetworkServiceSubnet), nil
}

// -----------------------------------------------------------------------------
// Bastion host IP configurations
// -----------------------------------------------------------------------------

type mqlAzureSubscriptionNetworkServiceBastionHostInternal struct {
	cacheIPConfigurations []*network.BastionHostIPConfiguration
}

func (a *mqlAzureSubscriptionNetworkServiceBastionHost) ipConfigurations() ([]any, error) {
	res := []any{}
	for _, ipConfig := range a.cacheIPConfigurations {
		if ipConfig == nil {
			continue
		}
		var provisioningState, privateIpAllocationMethod string
		var subnetId, publicIpAddressId *string
		if p := ipConfig.Properties; p != nil {
			if p.ProvisioningState != nil {
				provisioningState = string(*p.ProvisioningState)
			}
			if p.PrivateIPAllocationMethod != nil {
				privateIpAllocationMethod = string(*p.PrivateIPAllocationMethod)
			}
			if p.Subnet != nil {
				subnetId = p.Subnet.ID
			}
			if p.PublicIPAddress != nil {
				publicIpAddressId = p.PublicIPAddress.ID
			}
		}
		mqlConfig, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.bastionHost.ipConfiguration",
			map[string]*llx.RawData{
				"id":                        llx.StringDataPtr(ipConfig.ID),
				"name":                      llx.StringDataPtr(ipConfig.Name),
				"etag":                      llx.StringDataPtr(ipConfig.Etag),
				"provisioningState":         llx.StringData(provisioningState),
				"privateIpAllocationMethod": llx.StringData(privateIpAllocationMethod),
			})
		if err != nil {
			return nil, err
		}
		c := mqlConfig.(*mqlAzureSubscriptionNetworkServiceBastionHostIpConfiguration)
		c.cacheSubnetID = subnetId
		c.cachePublicIpAddressID = publicIpAddressId
		res = append(res, mqlConfig)
	}
	return res, nil
}

type mqlAzureSubscriptionNetworkServiceBastionHostIpConfigurationInternal struct {
	cacheSubnetID          *string
	cachePublicIpAddressID *string
}

func (a *mqlAzureSubscriptionNetworkServiceBastionHostIpConfiguration) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceBastionHostIpConfiguration) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	if a.cacheSubnetID == nil || *a.cacheSubnetID == "" {
		a.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.subnet", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cacheSubnetID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionNetworkServiceSubnet), nil
}

func (a *mqlAzureSubscriptionNetworkServiceBastionHostIpConfiguration) publicIpAddress() (*mqlAzureSubscriptionNetworkServiceIpAddress, error) {
	if a.cachePublicIpAddressID == nil || *a.cachePublicIpAddressID == "" {
		a.PublicIpAddress.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.ipAddress", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cachePublicIpAddressID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionNetworkServiceIpAddress), nil
}
