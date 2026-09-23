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
)

type mqlAzureSubscriptionNetworkServiceInterfaceIpConfigurationInternal struct {
	cacheSubnetId             *string
	cachePublicIpAddressId    *string
	cacheAppSecurityGroupIds  []string
	cacheVirtualNetworkTapIds []string
}

// ipConfigs builds the network interface's IP configurations as typed
// resources with resolvable subnet, public IP, and application security group
// references, from the raw configurations cached on the interface.
func (a *mqlAzureSubscriptionNetworkServiceInterface) ipConfigs() ([]any, error) {
	res := []any{}
	for _, ipConfig := range a.cacheIPConfigurations {
		if ipConfig == nil {
			continue
		}
		var provisioningState, privateIpAddress, privateIpAllocationMethod, privateIpAddressVersion string
		var primary bool
		var subnetId, publicIpAddressId *string
		var appSecurityGroupIds, virtualNetworkTapIds []string
		if p := ipConfig.Properties; p != nil {
			primary = convert.ToValue(p.Primary)
			privateIpAddress = convert.ToValue(p.PrivateIPAddress)
			if p.PrivateIPAllocationMethod != nil {
				privateIpAllocationMethod = string(*p.PrivateIPAllocationMethod)
			}
			if p.PrivateIPAddressVersion != nil {
				privateIpAddressVersion = string(*p.PrivateIPAddressVersion)
			}
			if p.ProvisioningState != nil {
				provisioningState = string(*p.ProvisioningState)
			}
			if p.Subnet != nil {
				subnetId = p.Subnet.ID
			}
			if p.PublicIPAddress != nil {
				publicIpAddressId = p.PublicIPAddress.ID
			}
			appSecurityGroupIds = appSecurityGroupIDs(p.ApplicationSecurityGroups)
			for _, tap := range p.VirtualNetworkTaps {
				if tap != nil && tap.ID != nil {
					virtualNetworkTapIds = append(virtualNetworkTapIds, *tap.ID)
				}
			}
		}
		mqlConfig, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.interface.ipConfiguration",
			map[string]*llx.RawData{
				"id":                        llx.StringDataPtr(ipConfig.ID),
				"name":                      llx.StringDataPtr(ipConfig.Name),
				"etag":                      llx.StringDataPtr(ipConfig.Etag),
				"provisioningState":         llx.StringData(provisioningState),
				"primary":                   llx.BoolData(primary),
				"privateIpAddress":          llx.StringData(privateIpAddress),
				"privateIpAllocationMethod": llx.StringData(privateIpAllocationMethod),
				"privateIpAddressVersion":   llx.StringData(privateIpAddressVersion),
			})
		if err != nil {
			return nil, err
		}
		c := mqlConfig.(*mqlAzureSubscriptionNetworkServiceInterfaceIpConfiguration)
		c.cacheSubnetId = subnetId
		c.cachePublicIpAddressId = publicIpAddressId
		c.cacheAppSecurityGroupIds = appSecurityGroupIds
		c.cacheVirtualNetworkTapIds = virtualNetworkTapIds
		res = append(res, mqlConfig)
	}
	return res, nil
}

// appSecurityGroupIDs flattens a slice of *ApplicationSecurityGroup into their
// ARM IDs, skipping nil entries and nil IDs.
func appSecurityGroupIDs(items []*network.ApplicationSecurityGroup) []string {
	var ids []string
	for _, asg := range items {
		if asg != nil && asg.ID != nil {
			ids = append(ids, *asg.ID)
		}
	}
	return ids
}

func (a *mqlAzureSubscriptionNetworkServiceInterfaceIpConfiguration) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceInterfaceIpConfiguration) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
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

func (a *mqlAzureSubscriptionNetworkServiceInterfaceIpConfiguration) publicIpAddress() (*mqlAzureSubscriptionNetworkServiceIpAddress, error) {
	if a.cachePublicIpAddressId == nil || *a.cachePublicIpAddressId == "" {
		a.PublicIpAddress.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.ipAddress", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cachePublicIpAddressId),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionNetworkServiceIpAddress), nil
}

func (a *mqlAzureSubscriptionNetworkServiceInterfaceIpConfiguration) applicationSecurityGroups() ([]any, error) {
	return azureResourceRefsByID(a.MqlRuntime, "azure.subscription.networkService.appSecurityGroup", a.cacheAppSecurityGroupIds)
}

func (a *mqlAzureSubscriptionNetworkServiceInterfaceIpConfiguration) virtualNetworkTaps() ([]any, error) {
	return azureResourceRefsByID(a.MqlRuntime, "azure.subscription.networkService.virtualNetworkTap", a.cacheVirtualNetworkTapIds)
}

// initAzureSubscriptionNetworkServiceIpAddress resolves a public IP address by
// its ARM ID so typed references to it (e.g. from a NIC IP configuration)
// populate fully.
func initAzureSubscriptionNetworkServiceIpAddress(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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
	name, err := azureId.Component("publicIPAddresses")
	if err != nil {
		return nil, nil, err
	}
	// The subscription's list already holds this public IP, and holds it for every
	// other reference to it too. Only pay for a Get when the list cannot
	// answer -- a reference into another subscription, or one since deleted.
	if ip := lookupInServiceList(runtime, ResourceAzureSubscriptionNetworkService,
		func(s *mqlAzureSubscriptionNetworkService) *plugin.TValue[[]any] { return s.GetPublicIpAddresses() },
		id); ip != nil {
		return args, ip, nil
	}

	client, err := network.NewPublicIPAddressesClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), azureId.ResourceGroup, name, nil)
	if err != nil {
		return nil, nil, err
	}
	mql, err := azureIpToMql(runtime, resp.PublicIPAddress)
	if err != nil {
		return nil, nil, err
	}
	return args, mql, nil
}

// initAzureSubscriptionNetworkServiceAppSecurityGroup resolves an application
// security group by its ARM ID so typed references to it (e.g. from a NIC IP
// configuration) populate fully.
func initAzureSubscriptionNetworkServiceAppSecurityGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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
	name, err := azureId.Component("applicationSecurityGroups")
	if err != nil {
		return nil, nil, err
	}
	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServiceAppSecurityGroup, id); cached != nil {
		return args, cached, nil
	}

	client, err := network.NewApplicationSecurityGroupsClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), azureId.ResourceGroup, name, nil)
	if err != nil {
		return nil, nil, err
	}
	mql, err := azureAppSecurityGroupToMql(runtime, resp.ApplicationSecurityGroup)
	if err != nil {
		return nil, nil, err
	}
	return args, mql, nil
}
